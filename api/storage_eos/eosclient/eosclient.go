package eosclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	osuser "os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cernbox/revaold/api"
	"github.com/gofrs/uuid"
	"go.uber.org/zap"
)

const (
	rootUser      = "root"
	rootGroup     = "root"
	versionPrefix = ".sys.v#."

	versionAquamarine = eosVersion("aquamarine")
	versionCitrine    = eosVersion("citrine")
)

type eosVersion string

type Options struct {
	// Location of the eos binary.
	// Default is /usr/bin/eos.
	EosBinary string

	// Location of the xrdcopy binary.
	// Default is /usr/bin/xrdcopy.
	XrdcopyBinary string

	// URL of the EOS MGM.
	// Default is root://eos-test.org
	URL string

	// Location on the local fs where to store reads.
	// Defaults to os.TempDir()
	CacheDirectory string

	// Enables logging of the commands executed
	// Defaults to false
	EnableLogging bool

	// Logger to use
	Logger *zap.Logger
}

func (opt *Options) init() {
	if opt.EosBinary == "" {
		opt.EosBinary = "/usr/bin/eos"
	}

	if opt.XrdcopyBinary == "" {
		opt.XrdcopyBinary = "/usr/bin/xrdcopy"
	}

	if opt.URL == "" {
		opt.URL = "root://eos-example.org"
	}

	if opt.CacheDirectory == "" {
		opt.CacheDirectory = os.TempDir()
	}

	if opt.Logger == nil {
		l, _ := zap.NewProduction()
		opt.Logger = l
	}
}

// Client performs actions against a EOS management node (MGM).
// It requires the eos-client and xrootd-client packages installed to work.
type Client struct {
	opt *Options
}

func New(opt *Options) (*Client, error) {
	opt.init()
	c := new(Client)
	c.opt = opt
	return c, nil
}

func getUnixUser(username string) (*osuser.User, error) {
	return osuser.Lookup(username)
}

// exec executes the command and returns the stdout, stderr and return code
func (c *Client) execute(cmd *exec.Cmd) (string, string, error) {
	cmd.Env = []string{
		"EOS_MGM_URL=" + c.opt.URL,
	}

	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	err := cmd.Run()

	var exitStatus int
	if exiterr, ok := err.(*exec.ExitError); ok {
		// The program has exited with an exit code != 0
		// This works on both Unix and Windows. Although package
		// syscall is generally platform dependent, WaitStatus is
		// defined for both Unix and Windows and in both cases has
		// an ExitStatus() method with the same signature.
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			exitStatus = status.ExitStatus()
			switch exitStatus {
			case 2:
				err = api.NewError(api.StorageNotFoundErrorCode)
			// eos reports back error code 22 when the user is not allowed to enter the instance
			case 22:
				err = api.NewError(api.StorageNotFoundErrorCode)
			}
		}
	}
	if c.opt.EnableLogging {
		c.opt.Logger.Info("eosclient: cmd", zap.String("args", fmt.Sprintf("%v", cmd.Args)), zap.Int("exist_status", exitStatus), zap.Error(err))
	}
	return outBuf.String(), errBuf.String(), err
}

func (c *Client) getVersion(ctx context.Context) (eosVersion, error) {
	unixUser, err := getUnixUser(rootUser)
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "version")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return "", err
	}
	return c.parseVersion(ctx, stdout), nil
}

func (c *Client) parseVersion(ctx context.Context, raw string) eosVersion {
	var serverVersion string
	rawLines := strings.Split(raw, "\n")
	for _, rl := range rawLines {
		if rl == "" {
			continue
		}
		if strings.HasPrefix(rl, "EOS_SERVER_VERSION") {
			serverVersion = strings.Split(strings.Split(rl, " ")[0], "=")[1]
			break
		}
	}

	if strings.HasPrefix(serverVersion, "4.") {
		return versionCitrine
	}
	return versionAquamarine
}

//Usage: eos acl [-l|--list] [-R|--recursive][--sys|--user] <rule> <path>
//
//    --help         Print help
//-R, --recursive    Apply on directories recursively
//-l, --list         List ACL rules
//    --user           Handle/list user.acl rules on directory
//    --sys            Handle/list sys.acl rules on directory
//<rule> is created based on chmod rules.
//Every rule begins with [u|g|egroup] followed with : and identifier.
//
//Afterwards can be:
//= for setting new permission .
//: for modification of existing permission.
//
//This is followed by the rule definition.
//Every ACL flag can be added with + or removed with -, or in case
//of setting new ACL permission just enter the ACL flag.
func (c *Client) addACLCitrine(ctx context.Context, username, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	var target = recipient.Identity
	if recipient.Type == api.ShareRecipient_USER {
		unixUser, err := getUnixUser(target)
		if err != nil {
			return err
		}
		target = unixUser.Uid
	}

	aclType := getAclType(recipient.Type)
	perm := getEosPerm(readOnly)

	// setting of the sys.acl is only possible from root user
	unixUser, err := getUnixUser(rootUser)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "acl", "--sys", "--recursive", fmt.Sprintf("%s:%s=%s", aclType, target, perm), path)
	_, _, err = c.execute(cmd)
	return err
}

func (c *Client) AddACL(ctx context.Context, username, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	version, err := c.getVersion(ctx)
	if err != nil {
		return err
	}

	if version == versionCitrine {
		return c.addACLCitrine(ctx, username, path, readOnly, recipient, shareList)
	}

	aclManager, err := c.getACLForPath(ctx, username, path)
	if err != nil {
		return err
	}

	switch recipient.Type {
	case api.ShareRecipient_USER:
		if err := aclManager.addUser(ctx, recipient.Identity, readOnly); err != nil {
			return err
		}
	case api.ShareRecipient_GROUP:
		if err := aclManager.addGroup(ctx, recipient.Identity, readOnly); err != nil {
			return err
		}
	case api.ShareRecipient_UNIX:
		if err := aclManager.addUnixGroup(ctx, recipient.Identity, readOnly); err != nil {
			return err
		}
	}

	sysAcl := aclManager.serialize()

	// setting of the sys.acl is only possible from root user
	unixUser, err := getUnixUser(rootUser)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "attr", "-r", "set", fmt.Sprintf("sys.acl=%s", sysAcl), path)
	_, _, err = c.execute(cmd)
	return err

}

func (c *Client) RemoveACL(ctx context.Context, username, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	version, err := c.getVersion(ctx)
	if err != nil {
		return err
	}

	if version == versionCitrine {
		return c.removeACLCitrine(ctx, username, path, recipient, shareList)
	}

	aclManager, err := c.getACLForPath(ctx, username, path)
	if err != nil {
		return err
	}

	switch recipient.Type {
	case api.ShareRecipient_USER:
		aclManager.deleteUser(ctx, recipient.Identity)
	case api.ShareRecipient_GROUP:
		aclManager.deleteGroup(ctx, recipient.Identity)
	case api.ShareRecipient_UNIX:
		aclManager.deleteUnixGroup(ctx, recipient.Identity)
	}

	sysAcl := aclManager.serialize()

	// setting of the sys.acl is only possible from root user
	unixUser, err := getUnixUser(rootUser)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "attr", "-r", "set", fmt.Sprintf("sys.acl=%s", sysAcl), path)
	_, _, err = c.execute(cmd)
	return err

}

func (c *Client) removeACLCitrine(ctx context.Context, username, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	var target = recipient.Identity
	if recipient.Type == api.ShareRecipient_USER {
		unixUser, err := getUnixUser(target)
		if err != nil {
			return err
		}
		target = unixUser.Uid
	}

	aclType := getAclType(recipient.Type)
	perm := "" // empty string will remove entry

	// setting of the sys.acl is only possible from root user
	unixUser, err := getUnixUser(rootUser)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "acl", "--sys", "--recursive", fmt.Sprintf("%s:%s=%s", aclType, target, perm), path)
	_, _, err = c.execute(cmd)
	return err
}

func (c *Client) UpdateACL(ctx context.Context, username, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return c.AddACL(ctx, username, path, readOnly, recipient, shareList)
}

func (c *Client) getACLForPath(ctx context.Context, username, path string) (*aclManager, error) {
	finfo, err := c.GetFileInfoByPath(ctx, username, path)
	if err != nil {
		return nil, err
	}

	aclManager := c.newAclManager(ctx, finfo.SysACL)
	return aclManager, nil
}

// GetFileInfoByInode returns the FileInfo by the given inode
func (c *Client) GetFileInfoByInode(ctx context.Context, username string, inode uint64) (*FileInfo, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "info", fmt.Sprintf("inode:%d", inode), "-m")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return c.parseFileInfo(stdout)
}

// GetFileInfoByPath returns the FilInfo at the given path
func (c *Client) GetFileInfoByPath(ctx context.Context, username, path string) (*FileInfo, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "info", path, "-m")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return c.parseFileInfo(stdout)
}

// GetQuota gets the quota of a user on the quota node defined by path
func (c *Client) GetQuota(ctx context.Context, username, path string) (int, int, error) {
	// setting of the sys.acl is only possible from root user
	unixUser, err := getUnixUser(rootUser)
	if err != nil {
		return 0, 0, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "quota", "ls", "-u", username, "-m")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return 0, 0, err
	}
	return c.parseQuota(path, stdout)
}

// CreateDir creates a directory at the given path
func (c *Client) CreateDir(ctx context.Context, username, path string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "mkdir", "-p", path)
	_, _, err = c.execute(cmd)
	return err
}

// Remove removes the resource at the given path
func (c *Client) Remove(ctx context.Context, username, path string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "rm", "-r", path)
	_, _, err = c.execute(cmd)
	return err
}

// Rename renames the resource referenced by oldPath to newPath
func (c *Client) Rename(ctx context.Context, username, oldPath, newPath string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "rename", oldPath, newPath)
	_, _, err = c.execute(cmd)
	return err
}

// List the contents of the directory given by path
func (c *Client) List(ctx context.Context, username, path string) ([]*FileInfo, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "find", "--fileinfo", "--maxdepth", "1", path)
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return c.parseFind(path, stdout)
}

// Read reads a file from the mgm
func (c *Client) Read(ctx context.Context, username, path string) (io.ReadCloser, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	uuid := uuid.Must(uuid.NewV4())
	rand := "eosread-" + uuid.String()
	localTarget := fmt.Sprintf("%s/%s", c.opt.CacheDirectory, rand)
	xrdPath := fmt.Sprintf("%s//%s", c.opt.URL, path)
	cmd := exec.CommandContext(ctx, "/usr/bin/xrdcopy", "--nopbar", "--silent", "-f", xrdPath, localTarget, fmt.Sprintf("-OSeos.ruid=%s&eos.rgid=%s&eos.app=reva_eosclient", unixUser.Uid, unixUser.Gid))
	_, _, err = c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return os.Open(localTarget)
}

// Write writes a file to the mgm
func (c *Client) Write(ctx context.Context, username, path string, stream io.ReadCloser) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	fd, err := ioutil.TempFile(c.opt.CacheDirectory, "eoswrite-")
	if err != nil {
		return err
	}
	defer fd.Close()
	defer os.RemoveAll(fd.Name())

	// copy stream to local temp file
	_, err = io.Copy(fd, stream)
	if err != nil {
		return err
	}
	xrdPath := fmt.Sprintf("%s//%s", c.opt.URL, path)
	cmd := exec.CommandContext(ctx, "/usr/bin/xrdcopy", "--nopbar", "--silent", "-f", fd.Name(), xrdPath, fmt.Sprintf("-ODeos.ruid=%s&eos.rgid=%s&eos.app=reva_eosclient", unixUser.Uid, unixUser.Gid))
	_, _, err = c.execute(cmd)
	return err
}

// ListDeletedEntries returns a list of the deleted entries.
func (c *Client) ListDeletedEntries(ctx context.Context, username string) ([]*DeletedEntry, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}

	// list only current day deletions to not kill the mgm when there are many files.
	today := time.Now().Format("2006/01/02")
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "recycle", "ls", today, "-m")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return parseRecycleList(stdout)
}

// RestoreDeletedEntry restores a deleted entry.
func (c *Client) RestoreDeletedEntry(ctx context.Context, username, key string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "recycle", "restore", key)
	_, _, err = c.execute(cmd)
	return err
}

// PurgeDeletedEntries purges all entries from the recycle bin.
func (c *Client) PurgeDeletedEntries(ctx context.Context, username string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "recycle", "purge")
	_, _, err = c.execute(cmd)
	return err
}

func getVersionFolder(p string) string {
	basename := path.Base(p)
	versionFolder := path.Join(path.Dir(p), versionPrefix+basename)
	return versionFolder
}

// ListVersions list all the versions for a given file.
func (c *Client) ListVersions(ctx context.Context, username, p string) ([]*FileInfo, error) {
	basename := path.Base(p)
	versionFolder := path.Join(path.Dir(p), versionPrefix+basename)
	finfos, err := c.List(ctx, username, versionFolder)
	if err != nil {
		// we send back an empty list
		return []*FileInfo{}, nil
	}
	return finfos, nil
}

// RollbackToVersion rollbacks a file to a previous version.
func (c *Client) RollbackToVersion(ctx context.Context, username, path, version string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "versions", path, version)
	_, _, err = c.execute(cmd)
	return err
}

// ReadVersion reads the version for the given file.
func (c *Client) ReadVersion(ctx context.Context, username, p, version string) (io.ReadCloser, error) {
	basename := path.Base(p)
	versionFile := path.Join(path.Dir(p), versionPrefix+basename, version)
	return c.Read(ctx, username, versionFile)
}

func parseRecycleList(raw string) ([]*DeletedEntry, error) {
	entries := []*DeletedEntry{}
	rawLines := strings.Split(raw, "\n")
	for _, rl := range rawLines {
		if rl == "" {
			continue
		}
		entry, err := parseRecycleEntry(rl)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parse entries like these:
// recycle=ls  recycle-bin=/eos/backup/proc/recycle/ uid=gonzalhu gid=it size=0 deletion-time=1510823151 type=recursive-dir keylength.restore-path=45 restore-path=/eos/scratch/user/g/gonzalhu/.sys.v#.app.ico/ restore-key=0000000000a35100
// recycle=ls  recycle-bin=/eos/backup/proc/recycle/ uid=gonzalhu gid=it size=381038 deletion-time=1510823151 type=file keylength.restore-path=36 restore-path=/eos/scratch/user/g/gonzalhu/app.ico restore-key=000000002544fdb3
func parseRecycleEntry(raw string) (*DeletedEntry, error) {
	partsBySpace := strings.Split(raw, " ")
	restoreKeyPair, partsBySpace := partsBySpace[len(partsBySpace)-1], partsBySpace[:len(partsBySpace)-1]
	restorePathPair := strings.Join(partsBySpace[9:], " ")

	partsBySpace = partsBySpace[:9]
	partsBySpace = append(partsBySpace, restorePathPair)
	partsBySpace = append(partsBySpace, restoreKeyPair)

	kv := getMap(partsBySpace)
	size, err := strconv.ParseUint(kv["size"], 10, 64)
	if err != nil {
		return nil, err
	}
	isDir := false
	if kv["type"] == "recursive-dir" {
		isDir = true
	}
	deletionMTime, err := strconv.ParseUint(strings.Split(kv["deletion-time"], ".")[0], 10, 64)
	if err != nil {
		return nil, err
	}
	entry := &DeletedEntry{
		RestorePath:   kv["restore-path"],
		RestoreKey:    kv["restore-key"],
		Size:          size,
		DeletionMTime: deletionMTime,
		IsDir:         isDir,
	}
	return entry, nil
}

func getMap(partsBySpace []string) map[string]string {
	kv := map[string]string{}
	for _, pair := range partsBySpace {
		parts := strings.Split(pair, "=")
		if len(parts) > 1 {
			kv[parts[0]] = parts[1]
		}

	}
	return kv
}

func (c *Client) parseFind(dirPath, raw string) ([]*FileInfo, error) {
	finfos := []*FileInfo{}
	rawLines := strings.Split(raw, "\n")
	for _, rl := range rawLines {
		if rl == "" {
			continue
		}
		fi, err := c.parseFileInfo(rl)
		if err != nil {
			return nil, err
		}
		// dirs in eos end with a slash, like /eos/user/g/gonzalhu/
		// we skip the current directory as eos find will return the directory we
		// ask to find
		if fi.File == path.Clean(dirPath)+"/" {
			continue
		}
		finfos = append(finfos, fi)
	}
	return finfos, nil
}

func (c Client) parseQuotaLine(line string) map[string]string {
	partsBySpace := strings.Split(line, " ")
	m := getMap(partsBySpace)
	return m
}
func (c *Client) parseQuota(path, raw string) (int, int, error) {
	rawLines := strings.Split(raw, "\n")
	for _, rl := range rawLines {
		if rl == "" {
			continue
		}

		m := c.parseQuotaLine(rl)
		// map[maxbytes:2000000000000 maxlogicalbytes:1000000000000 percentageusedbytes:0.49 quota:node uid:gonzalhu space:/eos/scratch/user/ usedbytes:9829986500 usedlogicalbytes:4914993250 statusfiles:ok usedfiles:334 maxfiles:1000000 statusbytes:ok]

		space := m["space"]
		if strings.HasPrefix(path, space) {
			maxBytesString, _ := m["maxlogicalbytes"]
			usedBytesString, _ := m["usedlogicalbytes"]
			maxBytes, _ := strconv.ParseInt(maxBytesString, 10, 64)
			usedBytes, _ := strconv.ParseInt(usedBytesString, 10, 64)
			return int(maxBytes), int(usedBytes), nil
		}
	}
	return 0, 0, nil
}

func (c *Client) parseFileInfo(raw string) (*FileInfo, error) {

	line := raw[15:]
	index := strings.Index(line, " file=/")
	lengthString := line[0:index]
	length, err := strconv.ParseUint(lengthString, 10, 64)
	if err != nil {
		return nil, err
	}

	line = line[index+6:] // skip ' file='
	name := line[0:length]

	kv := make(map[string]string)
	kv["file"] = name

	line = line[length+1:]
	partsBySpace := strings.Split(line, " ") // we have [size=45 container=3 ...}
	var previousXAttr = ""
	for _, p := range partsBySpace {
		partsByEqual := strings.Split(p, "=") // we have kv pairs like [size 14]
		if len(partsByEqual) == 2 {
			// handle xattrn and xattrv special cases
			if partsByEqual[0] == "xattrn" {
				previousXAttr = partsByEqual[1]
			} else if partsByEqual[0] == "xattrv" {
				kv[previousXAttr] = partsByEqual[1]
				previousXAttr = ""
			} else {
				kv[partsByEqual[0]] = partsByEqual[1]
			}
		}
	}

	fi, err := c.mapToFileInfo(kv)
	if err != nil {
		return nil, err
	}
	return fi, nil
}

// mapToFileInfo converts the dictionary to an usable structure.
// The kv has format:
// map[sys.forced.space:default files:0 mode:42555 ino:5 sys.forced.blocksize:4k sys.forced.layout:replica uid:0 fid:5 sys.forced.blockchecksum:crc32c sys.recycle:/eos/backup/proc/recycle/ fxid:00000005 pid:1 etag:5:0.000 keylength.file:4 file:/eos treesize:1931593933849913 container:3 gid:0 mtime:1498571294.108614409 ctime:1460121992.294326762 pxid:00000001 sys.forced.checksum:adler sys.forced.nstripes:2]
func (c *Client) mapToFileInfo(kv map[string]string) (*FileInfo, error) {
	inode, err := strconv.ParseUint(kv["ino"], 10, 64)
	if err != nil {
		return nil, err
	}
	fid, err := strconv.ParseUint(kv["fid"], 10, 64)
	if err != nil {
		return nil, err
	}

	var treeSize uint64
	// treeSize is only for containers, so we check
	if val, ok := kv["treesize"]; ok {
		treeSize, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	var fileCounter uint64
	// fileCounter is only for containers
	if val, ok := kv["files"]; ok {
		fileCounter, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	var dirCounter uint64
	// dirCounter is only for containers
	if val, ok := kv["container"]; ok {
		dirCounter, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	// treeCount is the number of entries under the tree
	treeCount := fileCounter + dirCounter

	var size uint64
	if val, ok := kv["size"]; ok {
		size, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	// mtime is split by a dot, we only take the first part, do we need subsec precision?
	mtime, err := strconv.ParseUint(strings.Split(kv["mtime"], ".")[0], 10, 64)
	if err != nil {
		return nil, err
	}

	// parse ctime if set
	var ctime uint64 = 0
	if val, ok := kv["ctime"]; ok && val != "" {
		val, _ := strconv.ParseUint(strings.Split(val, ".")[0], 10, 64)
		ctime = val
	}

	isDir := false
	if _, ok := kv["files"]; ok {
		isDir = true
	}

	fi := &FileInfo{
		File:      kv["file"],
		Inode:     inode,
		FID:       fid,
		ETag:      kv["etag"],
		Size:      size,
		TreeSize:  treeSize,
		MTime:     mtime,
		IsDir:     isDir,
		Instance:  c.opt.URL,
		SysACL:    kv["sys.acl"],
		TreeCount: treeCount,
		UID:       kv["uid"],
		GID:       kv["gid"],
		CTime:     ctime,
	}
	return fi, nil
}

type FileInfo struct {
	File      string `json:"eos_file"`
	Inode     uint64 `json:"inode"`
	FID       uint64 `json:"fid"`
	ETag      string
	TreeSize  uint64
	MTime     uint64
	Size      uint64
	IsDir     bool
	Instance  string
	SysACL    string
	TreeCount uint64
	UID       string
	GID       string
	CTime     uint64
}

type DeletedEntry struct {
	RestorePath   string
	RestoreKey    string
	Size          uint64
	DeletionMTime uint64
	IsDir         bool
}

type aclType string

var (
	errInvalidACL = errors.New("invalid acl")
)

const (
	aclTypeUser      aclType = "u"
	aclTypeGroup     aclType = "egroup"
	aclTypeUnixGroup aclType = "g"
)

type aclManager struct {
	aclEntries []*aclEntry
}

func (c *Client) newAclManager(ctx context.Context, sysAcl string) *aclManager {
	tokens := strings.Split(sysAcl, ",")
	aclEntries := []*aclEntry{}
	for _, t := range tokens {
		aclEntry, err := newAclEntry(ctx, t)
		if err != nil {
			c.opt.Logger.Warn("invalid acl entry", zap.String("sys.acl", sysAcl), zap.String("faulty_acl", t))
			continue
		}
		aclEntries = append(aclEntries, aclEntry)
	}

	return &aclManager{aclEntries: aclEntries}
}

func (m *aclManager) getUsers() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeUser {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getUsersWithReadPermission() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeUser && e.hasReadPermissions() {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getUsersWithWritePermission() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeUser && e.hasWritePermissions() {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getGroups() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeGroup {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getGroupsWithReadPermission() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeGroup && e.hasReadPermissions() {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getGroupsWithWritePermission() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeGroup && e.hasWritePermissions() {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getUnixGroups() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeUnixGroup {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getUnixGroupsWithReadPermission() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeUnixGroup && e.hasReadPermissions() {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getUnixGroupsWithWritePermission() []*aclEntry {
	entries := []*aclEntry{}
	for _, e := range m.aclEntries {
		if e.aclType == aclTypeUnixGroup && e.hasWritePermissions() {
			entries = append(entries, e)
		}
	}
	return entries
}

func (m *aclManager) getUser(username string) *aclEntry {
	for _, u := range m.getUsers() {
		if u.recipient == username {
			return u
		}
	}
	return nil
}

func (m *aclManager) getGroup(group string) *aclEntry {
	for _, e := range m.getGroups() {
		if e.recipient == group {
			return e
		}
	}
	return nil
}

func (m *aclManager) getUnixGroup(unixGroup string) *aclEntry {
	for _, e := range m.getUnixGroups() {
		if e.recipient == unixGroup {
			return e
		}
	}
	return nil
}

func (m *aclManager) deleteUser(ctx context.Context, username string) error {
	for i, e := range m.aclEntries {
		if e.recipient == username && e.aclType == aclTypeUser {
			m.aclEntries = append(m.aclEntries[:i], m.aclEntries[i+1:]...)
		}
	}
	return nil
}

func (m *aclManager) addUser(ctx context.Context, username string, readOnly bool) error {
	m.deleteUser(ctx, username)

	perm := getEosPerm(readOnly)
	sysAcl := strings.Join([]string{string(aclTypeUser), username, perm}, ":")
	newEntry, err := newAclEntry(ctx, sysAcl)
	if err != nil {
		return err
	}
	m.aclEntries = append(m.aclEntries, newEntry)
	return nil
}

func (m *aclManager) deleteGroup(ctx context.Context, group string) {
	for i, e := range m.aclEntries {
		if e.recipient == group && e.aclType == aclTypeGroup {
			m.aclEntries = append(m.aclEntries[:i], m.aclEntries[i+1:]...)
			return
		}
	}
}

func (m *aclManager) addGroup(ctx context.Context, group string, readOnly bool) error {
	m.deleteGroup(ctx, group)
	perm := getEosPerm(readOnly)
	sysAcl := strings.Join([]string{string(aclTypeGroup), group, perm}, ":")
	newEntry, err := newAclEntry(ctx, sysAcl)
	if err != nil {
		return err
	}
	m.aclEntries = append(m.aclEntries, newEntry)
	return nil
}

func (m *aclManager) deleteUnixGroup(ctx context.Context, unixGroup string) {
	for i, e := range m.aclEntries {
		if e.recipient == unixGroup && e.aclType == aclTypeUnixGroup {
			m.aclEntries = append(m.aclEntries[:i], m.aclEntries[i+1:]...)
			return
		}
	}
}

func (m *aclManager) addUnixGroup(ctx context.Context, unixGroup string, readOnly bool) error {
	m.deleteUnixGroup(ctx, unixGroup)
	perm := getEosPerm(readOnly)
	sysAcl := strings.Join([]string{string(aclTypeUnixGroup), unixGroup, perm}, ":")
	newEntry, err := newAclEntry(ctx, sysAcl)
	if err != nil {
		return err
	}
	m.aclEntries = append(m.aclEntries, newEntry)
	return nil
}

func getEosPerm(readOnly bool) string {
	if readOnly {
		return "rx"
	}
	return "rwx+d"
}

func (m *aclManager) serialize() string {
	sysAcl := []string{}
	for _, e := range m.aclEntries {
		sysAcl = append(sysAcl, e.serialize())
	}
	return strings.Join(sysAcl, ",")
}

type aclEntry struct {
	aclType     aclType
	recipient   string
	permissions string
}

// u:gonzalhu:rw
func newAclEntry(ctx context.Context, singleSysAcl string) (*aclEntry, error) {
	tokens := strings.Split(singleSysAcl, ":")
	if len(tokens) != 3 {
		return nil, errInvalidACL
	}
	return &aclEntry{
		aclType:     aclType(tokens[0]),
		recipient:   tokens[1],
		permissions: tokens[2],
	}, nil
}

func (a *aclEntry) hasWritePermissions() bool {
	return strings.Index(a.permissions, "w") != -1
}

func (a *aclEntry) hasReadPermissions() bool {
	return strings.Index(a.permissions, "r") != -1
}

func (a *aclEntry) serialize() string {
	return strings.Join([]string{string(a.aclType), a.recipient, a.permissions}, ":")
}

func getAclType(t api.ShareRecipient_RecipientType) aclType {
	switch t {
	case api.ShareRecipient_USER:
		return aclTypeUser
	case api.ShareRecipient_GROUP:
		return aclTypeGroup
	default:
		return aclTypeUnixGroup
	}
}
