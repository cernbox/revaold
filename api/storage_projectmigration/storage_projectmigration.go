package storage_projectmigration

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/cernbox/revaold/api"
	"go.uber.org/zap"

	cbox_api "github.com/cernbox/cboxredirectd/api"
)

type eosStorage struct {
	logger   *zap.Logger
	migrator cbox_api.Migrator

	oldProject    api.Storage
	newProjectMap map[string]api.Storage
}

type Options struct {
	Logger   *zap.Logger
	Migrator cbox_api.Migrator

	OldProject    api.Storage
	NewProjectMap map[string]api.Storage
}

func (opt *Options) init() {
	if opt.Logger == nil {
		l, _ := zap.NewProduction()
		opt.Logger = l
	}
}

func New(opt *Options) (api.Storage, error) {
	opt.init()

	eosStorage := &eosStorage{
		logger:        opt.Logger,
		oldProject:    opt.OldProject,
		newProjectMap: opt.NewProjectMap,
		migrator:      opt.Migrator,
	}
	return eosStorage, nil
}

func (fs *eosStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	//return id, nil
	// we don't support access by fileid on this storage
	return "", api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *eosStorage) getStorageForProject(ctx context.Context, fn string) (api.Storage, string, string) {
	// obtain letter from path
	relative := strings.TrimPrefix(fn, "/")
	parts := strings.Split(relative, "/") // ["l", "labradorprojecttest"]
	fs.logger.Debug("migration: home project: fn=" + fn)
	if len(parts) < 2 {
		fs.logger.Info("migration: forwarding project request to oldproject", zap.String("path", fn))
		return fs.oldProject, "oldproject", "/old/project"
	}
	letter := parts[0]      // "l"
	projectName := parts[1] // "labradorprojecttest"
	key := fmt.Sprintf("/eos/project/%s/%s", letter, projectName)
	fs.logger.Debug("migration: key", zap.String("key", key))

	migrated := fs.isProjectMigrated(ctx, key)

	if !migrated {
		fs.logger.Info("migration: forwarding project request to oldproject", zap.String("path", fn))
		return fs.oldProject, "oldproject", "/old/project"
	}

	s, mountID, mountPrefix := fs.getStorageForLetter(ctx, letter)
	fs.logger.Info("migration: forwarding project request to newproject", zap.String("path", fn))
	return s, mountID, mountPrefix
}

func (fs *eosStorage) getStorageForLetter(ctx context.Context, letter string) (api.Storage, string, string) {
	s, ok := fs.newProjectMap[letter]
	if !ok {
		panic("storage not found for letter: " + letter)
	}
	mountID := fmt.Sprintf("newproject-%s", letter)
	mountPrefix := fmt.Sprintf("/new/project/%s", letter)
	return s, mountID, mountPrefix
}

func (fs *eosStorage) isProjectMigrated(ctx context.Context, key string) bool {
	defaultProjectNotFound := fs.migrator.GetDefaultProjectNotFound(ctx)
	migrated, found := fs.migrator.IsKeyMigrated(ctx, key)
	if !found {
		// if not found, we apply the default value
		if defaultProjectNotFound == cbox_api.DefaultNonDAVRequestNewProxy {
			fs.logger.Info("key not found, applying default", zap.String("key", key), zap.String("project", "newproject"))
			return true
		} else {
			fs.logger.Info("key not found, applying default", zap.String("key", key), zap.String("project", "oldproject"))
			return false
		}
	}
	return migrated
}

func (fs *eosStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.SetACL(ctx, path, readOnly, recipient, shareList)

}

func (fs *eosStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.UnsetACL(ctx, path, recipient, shareList)

}

func (fs *eosStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.UpdateACL(ctx, path, readOnly, recipient, shareList)
}

func (fs *eosStorage) GetQuota(ctx context.Context, p string) (int, int, error) {
	ts, _, _ := fs.getStorageForProject(ctx, p)
	return ts.GetQuota(ctx, p)

}

func (fs *eosStorage) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	ts, mountID, mountPrefix := fs.getStorageForProject(ctx, p)
	md, err := ts.GetMetadata(ctx, p)
	if err != nil {
		return nil, err
	}

	migID := fmt.Sprintf("%s:%s", mountID, md.Id)
	migPath := path.Join(mountPrefix, md.Path)

	md.MigId = migID
	md.MigPath = migPath

	return md, nil

}

func (fs *eosStorage) ListFolder(ctx context.Context, p string) ([]*api.Metadata, error) {
	ts, mountID, mountPrefix := fs.getStorageForProject(ctx, p)
	mds, err := ts.ListFolder(ctx, p)
	if err != nil {
		return nil, err
	}

	for _, md := range mds {
		migID := fmt.Sprintf("%s:%s", mountID, md.Id)
		migPath := path.Join(mountPrefix, md.Path)

		md.MigId = migID
		md.MigPath = migPath
	}

	return mds, nil
}

func (fs *eosStorage) CreateDir(ctx context.Context, path string) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.CreateDir(ctx, path)
}

func (fs *eosStorage) Delete(ctx context.Context, path string) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.Delete(ctx, path)
}

func (fs *eosStorage) Move(ctx context.Context, oldPath, newPath string) error {
	ts, _, _ := fs.getStorageForProject(ctx, oldPath)
	return ts.Move(ctx, oldPath, newPath)
}

func (fs *eosStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.Download(ctx, path)
}

func (fs *eosStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.Upload(ctx, path, r)
}

func (fs *eosStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.ListRevisions(ctx, path)
}

func (fs *eosStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.DownloadRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.RestoreRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) EmptyRecycle(ctx context.Context, path string) error {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.EmptyRecycle(ctx, path)
}

func (fs *eosStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	ts, _, _ := fs.getStorageForProject(ctx, path)
	return ts.ListRecycle(ctx, path)
}

func (fs *eosStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	ts, _, _ := fs.getStorageForProject(ctx, restoreKey)
	return ts.RestoreRecycleEntry(ctx, restoreKey)
}
