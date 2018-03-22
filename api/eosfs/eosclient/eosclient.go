package eosclient

import (
	"bytes"
	"context"
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

	"github.com/cernbox/reva/api"
	"github.com/satori/go.uuid"
)

const versionPrefix = ".sys.v#."

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

	// Logger to log
	// Defaults to stdout
	Logger Logger

	// Enables logging of the commands executed
	// Defaults to false
	EnableLogging bool
}

type Logger interface {
	Log(msg string)
}

type defaultLogger struct{}

func (l *defaultLogger) Log(msg string) {
	fmt.Fprintln(os.Stdout, msg)
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
		opt.Logger = new(defaultLogger)
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
	if c.opt.EnableLogging {
		c.opt.Logger.Log(fmt.Sprintf("%+v", cmd))
	}
	if exiterr, ok := err.(*exec.ExitError); ok {
		// The program has exited with an exit code != 0
		// This works on both Unix and Windows. Although package
		// syscall is generally platform dependent, WaitStatus is
		// defined for both Unix and Windows and in both cases has
		// an ExitStatus() method with the same signature.
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			switch status.ExitStatus() {
			case 2:
				err = api.NewError(api.StorageNotFoundErrorCode)
			}
		}
	}
	return outBuf.String(), errBuf.String(), err
}

// GetFileInfoByInode returns the FileInfo by the given inode
func (c *Client) GetFileInfoByInode(ctx context.Context, username string, inode uint64) (*FileInfo, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "info", fmt.Sprintf("inode:%d", inode), "-m")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return parseFileInfo(stdout)
}

// GetFileInfoByPath returns the FilInfo at the given path
func (c *Client) GetFileInfoByPath(ctx context.Context, username, path string) (*FileInfo, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "info", path, "-m")
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return parseFileInfo(stdout)
}

// CreateDir creates a directory at the given path
func (c *Client) CreateDir(ctx context.Context, username, path string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}

	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "mkdir", "-p", path)
	_, _, err = c.execute(cmd)
	return err
}

// Remove removes the resource at the given path
func (c *Client) Remove(ctx context.Context, username, path string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "rm", "-r", path)
	_, _, err = c.execute(cmd)
	return err
}

// Rename renames the resource referenced by oldPath to newPath
func (c *Client) Rename(ctx context.Context, username, oldPath, newPath string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "rename", oldPath, newPath)
	_, _, err = c.execute(cmd)
	return err
}

// List the contents of the directory given by path
func (c *Client) List(ctx context.Context, username, path string) ([]*FileInfo, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "find", "--fileinfo", "--maxdepth", "1", path)
	stdout, _, err := c.execute(cmd)
	if err != nil {
		return nil, err
	}
	return parseFind(path, stdout)
}

// Read reads a file from the mgm
func (c *Client) Read(ctx context.Context, username, path string) (io.ReadCloser, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	uuid, _ := uuid.NewV4()
	rand := uuid.String()
	localTarget := fmt.Sprintf("%s/%s", c.opt.CacheDirectory, rand)
	xrdPath := fmt.Sprintf("%s//%s", c.opt.URL, path)
	cmd := exec.Command("/usr/bin/xrdcopy", "--nopbar", "--silent", "-f", xrdPath, localTarget, fmt.Sprintf("-OSeos.ruid=%s&eos.rgid=%s", unixUser.Uid, unixUser.Gid))
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
	fd, err := ioutil.TempFile(c.opt.CacheDirectory, "eoswrite")
	if err != nil {
		return err
	}
	// copy stream to local temp file
	_, err = io.Copy(fd, stream)
	if err != nil {
		return err
	}
	xrdPath := fmt.Sprintf("%s//%s", c.opt.URL, path)
	cmd := exec.Command("/usr/bin/xrdcopy", "--nopbar", "--silent", "-f", fd.Name(), xrdPath, fmt.Sprintf("-ODeos.ruid=%s&eos.rgid=%d", unixUser.Uid, unixUser.Gid))
	_, _, err = c.execute(cmd)
	return err
}

// ListDeletedEntries returns a list of the deleted entries.
func (c *Client) ListDeletedEntries(ctx context.Context, username string) ([]*DeletedEntry, error) {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return nil, err
	}
	// TODO(labkode): add protection if slave is configured and alive to count how many files are in the trashbin before
	// triggering the recycle ls call that could break the instance because of unavailable memory.
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "recycle", "ls", "-m")
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
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "recycle", "restore", key)
	_, _, err = c.execute(cmd)
	return err
}

// PurgeDeletedEntries purges all entries from the recycle bin.
func (c *Client) PurgeDeletedEntries(ctx context.Context, username string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "recycle", "purge")
	_, _, err = c.execute(cmd)
	return err
}

// ListVersions list all the versions for a given file.
func (c *Client) ListVersions(ctx context.Context, username, p string) ([]*FileInfo, error) {
	basename := path.Base(p)
	versionFolder := path.Join(path.Dir(p), versionPrefix+basename)
	return c.List(ctx, username, versionFolder)
}

// RollbackToVersion rollbacks a file to a previous version.
func (c *Client) RollbackToVersion(ctx context.Context, username, path, version string) error {
	unixUser, err := getUnixUser(username)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/eos", "-r", unixUser.Uid, unixUser.Gid, "file", "versions", path, version)
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

func parseFind(dirPath, raw string) ([]*FileInfo, error) {
	finfos := []*FileInfo{}
	rawLines := strings.Split(raw, "\n")
	for _, rl := range rawLines {
		if rl == "" {
			continue
		}
		fi, err := parseFileInfo(rl)
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

func parseFileInfo(raw string) (*FileInfo, error) {
	kv := make(map[string]string)
	partsBySpace := strings.Split(raw, " ") // we have [keylength.file=14 file=/eos/pps/proc/ container=3 ...}
	var previousXAttr = ""
	for _, p := range partsBySpace {
		partsByEqual := strings.Split(p, "=") // we have kv pairs like [ keylength.file 14]
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

	// fix eos path because the kv pair file=path could contains whitespace and the whitespace is the pair separator. Not very smart :(
	fileLength := kv["keylength.file"]
	fileLengthInt64, err := strconv.ParseInt(fileLength, 10, 64)
	if err != nil {
		return nil, err
	}
	startIndex := int64(14) + int64(len(fileLength)) + 7
	kv["file"] = raw[startIndex : startIndex+fileLengthInt64]

	fi, err := mapToFileInfo(kv)
	if err != nil {
		return nil, err
	}
	return fi, nil
}

// mapToFileInfo converts the dictionary to an usable structure.
// The kv has format:
// map[sys.forced.space:default files:0 mode:42555 ino:5 sys.forced.blocksize:4k sys.forced.layout:replica uid:0 fid:5 sys.forced.blockchecksum:crc32c sys.recycle:/eos/backup/proc/recycle/ fxid:00000005 pid:1 etag:5:0.000 keylength.file:4 file:/eos treesize:1931593933849913 container:3 gid:0 mtime:1498571294.108614409 ctime:1460121992.294326762 pxid:00000001 sys.forced.checksum:adler sys.forced.nstripes:2]
func mapToFileInfo(kv map[string]string) (*FileInfo, error) {
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

	isDir := false
	if _, ok := kv["files"]; ok {
		isDir = true
	}

	fi := &FileInfo{
		File:     kv["file"],
		Inode:    inode,
		FID:      fid,
		ETag:     kv["etag"],
		Size:     size,
		TreeSize: treeSize,
		MTime:    mtime,
		IsDir:    isDir,
	}
	return fi, nil
}

type FileInfo struct {
	File     string
	Inode    uint64
	FID      uint64
	ETag     string
	TreeSize uint64
	MTime    uint64
	Size     uint64
	IsDir    bool
}

type DeletedEntry struct {
	RestorePath   string
	RestoreKey    string
	Size          uint64
	DeletionMTime uint64
	IsDir         bool
}
