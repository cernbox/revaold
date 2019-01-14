package storage_eos

import (
	"context"
	"fmt"
	"io"
	"os"
	gopath "path"
	"regexp"
	"strconv"
	"strings"

	"github.com/cernbox/revaold/api"
	"github.com/cernbox/revaold/api/storage_eos/eosclient"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

var hiddenReg = regexp.MustCompile(`\.sys\..#.`)

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}

type eosStorage struct {
	c             *eosclient.Client
	mountpoint    string
	logger        *zap.Logger
	showHiddenSys bool
	forceReadOnly bool
}

type Options struct {
	// Namespace for path operations
	Namespace string `json:"namespace"`

	Logger *zap.Logger

	// Location of the eos binary.
	// Default is /usr/bin/eos.
	EosBinary string `json:"eos_binary"`

	// Location of the xrdcopy binary.
	// Default is /usr/bin/xrdcopy.
	XrdcopyBinary string `json:"xrdcopy_binary"`

	// URL of the Master EOS MGM.
	// Default is root://eos-test.org
	MasterURL string `json:"master_url"`

	// URL of the Slave EOS MGM.
	// Default is root://eos-test.org
	SlaveURL string `json:"slave_url"`

	// Location on the local fs where to store reads.
	// Defaults to os.TempDir()
	CacheDirectory string `json:"cache_directory"`

	// Enables logging of the commands executed
	// Defaults to false
	EnableLogging bool `json:"enable_logging"`

	// ShowHiddenSysFiles shows internal EOS files like
	// .sys.v# and .sys.a# files.
	ShowHiddenSysFiles bool `json:"show_hidden_sys_files"`

	// ForceReadOnly does not allow writes into the storage.
	ForceReadOnly bool `json:"force_read_only"`
}

func (opt *Options) init() {
	opt.Namespace = gopath.Clean(opt.Namespace)
	if !strings.HasPrefix(opt.Namespace, "/") {
		opt.Namespace = "/"
	}

	if opt.EosBinary == "" {
		opt.EosBinary = "/usr/bin/eos"
	}

	if opt.XrdcopyBinary == "" {
		opt.XrdcopyBinary = "/usr/bin/xrdcopy"
	}

	if opt.MasterURL == "" {
		opt.MasterURL = "root://eos-example.org"
	}

	if opt.SlaveURL == "" {
		opt.SlaveURL = opt.MasterURL
	}

	if opt.CacheDirectory == "" {
		opt.CacheDirectory = os.TempDir()
	}

	if opt.Logger == nil {
		l, _ := zap.NewProduction()
		opt.Logger = l
	}
}

func New(opt *Options) (api.Storage, error) {
	opt.init()

	eosClientOpts := &eosclient.Options{
		XrdcopyBinary:  opt.XrdcopyBinary,
		URL:            opt.MasterURL,
		EosBinary:      opt.EosBinary,
		EnableLogging:  opt.EnableLogging,
		CacheDirectory: opt.CacheDirectory,
		Logger:         opt.Logger,
	}
	eosClient, err := eosclient.New(eosClientOpts)
	if err != nil {
		return nil, err
	}

	eosStorage := &eosStorage{
		c:             eosClient,
		logger:        opt.Logger,
		mountpoint:    opt.Namespace,
		showHiddenSys: opt.ShowHiddenSysFiles,
		forceReadOnly: opt.ForceReadOnly,
	}
	return eosStorage, nil
}

func (fs *eosStorage) getInternalPath(ctx context.Context, path string) string {
	l := ctx_zap.Extract(ctx)
	internalPath := gopath.Join(fs.mountpoint, path)
	l.Debug("path conversion: external => internal", zap.String("external", path), zap.String("internal", internalPath))
	return internalPath
}

func (fs *eosStorage) removeNamespace(np string) string {
	p := strings.TrimPrefix(np, fs.mountpoint)
	if p == "" {
		p = "/"
	}
	fs.logger.Debug("path conversion: internal => external", zap.String("internal", np), zap.String("external", p))
	return p
}

func (fs *eosStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return "", err
	}

	// parts[0] = 868317, parts[1] = photos, ...
	parts := strings.Split(id, "/")
	fileId, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return "", err
	}

	eosFileInfo, err := fs.c.GetFileInfoByInode(ctx, u.AccountId, fileId)
	if err != nil {
		return "", err
	}

	fi := fs.convertToMetadata(eosFileInfo)
	return fi.Path, nil
}

func (fs *eosStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	path = fs.getInternalPath(ctx, path)
	return fs.c.AddACL(ctx, u.AccountId, path, readOnly, recipient, shareList)

}

func (fs *eosStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	path = fs.getInternalPath(ctx, path)
	return fs.c.RemoveACL(ctx, u.AccountId, path, recipient, shareList)

}

func (fs *eosStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	path = fs.getInternalPath(ctx, path)
	return fs.c.AddACL(ctx, u.AccountId, path, readOnly, recipient, shareList)
}

func (fs *eosStorage) GetMetadata(ctx context.Context, path string) (*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = fs.getInternalPath(ctx, path)
	eosFileInfo, err := fs.c.GetFileInfoByPath(ctx, u.AccountId, path)
	if err != nil {
		return nil, err
	}
	fi := fs.convertToMetadata(eosFileInfo)
	if fs.forceReadOnly {
		fi.IsReadOnly = true
	}
	return fi, nil
}

func (fs *eosStorage) ListFolder(ctx context.Context, path string) ([]*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = fs.getInternalPath(ctx, path)
	eosFileInfos, err := fs.c.List(ctx, u.AccountId, path)
	if err != nil {
		return nil, err
	}
	finfos := []*api.Metadata{}
	for _, eosFileInfo := range eosFileInfos {
		// filter out sys files
		if !fs.showHiddenSys {
			base := gopath.Base(eosFileInfo.File)
			if hiddenReg.MatchString(base) {
				continue
			}

		}

		finfo := fs.convertToMetadata(eosFileInfo)
		if fs.forceReadOnly {
			finfo.IsReadOnly = true
		}

		finfos = append(finfos, finfo)
	}
	return finfos, nil
}

func (fs *eosStorage) GetQuota(ctx context.Context, path string) (int, int, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.GetQuota(ctx, u.AccountId, path)
}

func (fs *eosStorage) CreateDir(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.CreateDir(ctx, u.AccountId, path)
}

func (fs *eosStorage) Delete(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.Remove(ctx, u.AccountId, path)
}

func (fs *eosStorage) Move(ctx context.Context, oldPath, newPath string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	oldPath = fs.getInternalPath(ctx, oldPath)
	newPath = fs.getInternalPath(ctx, newPath)
	return fs.c.Rename(ctx, u.AccountId, oldPath, newPath)
}

func (fs *eosStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.Read(ctx, u.AccountId, path)
}

func (fs *eosStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.Write(ctx, u.AccountId, path, r)
}

func (fs *eosStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = fs.getInternalPath(ctx, path)
	eosRevisions, err := fs.c.ListVersions(ctx, u.AccountId, path)
	if err != nil {
		return nil, err
	}
	revisions := []*api.Revision{}
	for _, eosRev := range eosRevisions {
		rev := fs.convertToRevision(eosRev)
		revisions = append(revisions, rev)
	}
	return revisions, nil
}

func (fs *eosStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.ReadVersion(ctx, u.AccountId, path, revisionKey)
}

func (fs *eosStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, path)
	return fs.c.RollbackToVersion(ctx, u.AccountId, path, revisionKey)
}

func (fs *eosStorage) EmptyRecycle(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	return fs.c.PurgeDeletedEntries(ctx, u.AccountId)
}

func (fs *eosStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	eosDeletedEntries, err := fs.c.ListDeletedEntries(ctx, u.AccountId)
	if err != nil {
		return nil, err
	}
	recycleEntries := []*api.RecycleEntry{}
	for _, entry := range eosDeletedEntries {
		if !fs.showHiddenSys {
			base := gopath.Base(entry.RestorePath)
			if hiddenReg.MatchString(base) {
				continue
			}

		}
		recycleEntry := fs.convertToRecycleEntry(entry)
		recycleEntries = append(recycleEntries, recycleEntry)
	}
	return recycleEntries, nil
}

func (fs *eosStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	return fs.c.RestoreDeletedEntry(ctx, u.AccountId, restoreKey)
}

func (fs *eosStorage) convertToRecycleEntry(eosDeletedEntry *eosclient.DeletedEntry) *api.RecycleEntry {
	recycleEntry := &api.RecycleEntry{
		RestorePath: fs.removeNamespace(eosDeletedEntry.RestorePath),
		RestoreKey:  eosDeletedEntry.RestoreKey,
		Size:        eosDeletedEntry.Size,
		DelMtime:    eosDeletedEntry.DeletionMTime,
		IsDir:       eosDeletedEntry.IsDir,
	}
	return recycleEntry
}

func (fs *eosStorage) convertToRevision(eosFileInfo *eosclient.FileInfo) *api.Revision {
	md := fs.convertToMetadata(eosFileInfo)
	revision := &api.Revision{
		RevKey: gopath.Base(md.Path),
		Size:   md.Size,
		Mtime:  md.Mtime,
		IsDir:  md.IsDir,
	}
	return revision
}
func (fs *eosStorage) convertToMetadata(eosFileInfo *eosclient.FileInfo) *api.Metadata {
	finfo := new(api.Metadata)
	finfo.Id = fmt.Sprintf("%d", eosFileInfo.Inode)
	finfo.Path = fs.removeNamespace(eosFileInfo.File)
	finfo.Mtime = eosFileInfo.MTime
	finfo.IsDir = eosFileInfo.IsDir
	finfo.Etag = eosFileInfo.ETag
	if finfo.IsDir {
		finfo.TreeCount = eosFileInfo.TreeCount
		finfo.Size = eosFileInfo.TreeSize
	} else {
		finfo.Size = eosFileInfo.Size
	}
	finfo.EosFile = eosFileInfo.File
	finfo.EosInstance = eosFileInfo.Instance
	finfo.Mime = api.DetectMimeType(finfo.IsDir, finfo.Path)
	finfo.IsShareable = true
	return finfo
}
