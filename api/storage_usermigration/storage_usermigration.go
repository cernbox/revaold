package storage_usermigration

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

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}

type eosStorage struct {
	logger   *zap.Logger
	migrator cbox_api.Migrator

	oldUser    api.Storage
	newUserMap map[string]api.Storage
}

type Options struct {
	Logger   *zap.Logger
	Migrator cbox_api.Migrator

	OldUser    api.Storage
	NewUserMap map[string]api.Storage
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
		logger:     opt.Logger,
		oldUser:    opt.OldUser,
		newUserMap: opt.NewUserMap,
		migrator:   opt.Migrator,
	}
	return eosStorage, nil
}

func (fs *eosStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	return id, nil
	// we don't support access by fileid on this storage
	return "", api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *eosStorage) getStorageForLetter(ctx context.Context, letter string) (api.Storage, string, string) {
	s, ok := fs.newUserMap[letter]
	if !ok {
		panic("storage not found for letter: " + letter)
	}
	mountID := fmt.Sprintf("newuser-%s", letter)
	mountPrefix := fmt.Sprintf("/new/user/%s", letter)
	return s, mountID, mountPrefix
}

func (fs *eosStorage) getStorageForPath(ctx context.Context, letterPath string) (api.Storage, string, string, string) {
	var key, letter string
	tokens := strings.Split(strings.TrimPrefix(letterPath, "/"), "/")
	if len(tokens) > 1 {
		letter = tokens[0]
		if len(tokens[0]) == 1 { // l/labradorsvc
			key = path.Join(key, path.Join(tokens[0:2]...))
		} else {
			key = path.Join(key, tokens[0]) // csc/Docs
		}
	}

	if len(tokens) == 1 {
		key = path.Join(key, tokens[0])
	}

	// add /eos/user to the key
	key = path.Join("/eos/user", key)

	fs.logger.Debug("migration key", zap.String("key", key))

	migrated := fs.isPathMigrated(ctx, key)

	if !migrated {
		fs.logger.Info("forwarding to olduser", zap.String("path", letterPath))
		return fs.oldUser, "olduser", "/old/user", letterPath
	}

	s, mountID, mountPrefix := fs.getStorageForLetter(ctx, letter)
	fs.logger.Info("forwarding to newuser", zap.String("path", letterPath))
	// remove letter as /new/user/l mount already contains letter info
	return s, mountID, mountPrefix, strings.TrimPrefix(letterPath, fmt.Sprintf("/%s", letter))
}

func (fs *eosStorage) isPathMigrated(ctx context.Context, key string) bool {
	defaultUserNotFound := fs.migrator.GetDefaultUserNotFound(ctx)
	migrated, found := fs.migrator.IsKeyMigrated(ctx, key)
	if !found {
		// if not found, we apply the default value
		if defaultUserNotFound == cbox_api.DefaultUserNotFoundNewProxy {
			fs.logger.Info("key not found, applying default", zap.String("key", key), zap.String("instance", "eosuser"))
			return true
		} else {
			fs.logger.Info("key not found, applying default", zap.String("key", key), zap.String("instance", "eoshome"))
			return false
		}
	}
	return migrated
}

func (fs *eosStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.SetACL(ctx, path, readOnly, recipient, shareList)

}

func (fs *eosStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.UnsetACL(ctx, path, recipient, shareList)

}

func (fs *eosStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.UpdateACL(ctx, path, readOnly, recipient, shareList)
}

func (fs *eosStorage) GetQuota(ctx context.Context, p string) (int, int, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	ts, _, _, p := fs.getStorageForPath(ctx, p)
	return ts.GetQuota(ctx, p)

}
func (fs *eosStorage) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts, mountID, mountPrefix, p := fs.getStorageForPath(ctx, p)
	md, err := ts.GetMetadata(ctx, p)
	if err != nil {
		return nil, err
	}

	md.Path = fs.getTargetMetadataPath(mountPrefix, p)
	migID := fmt.Sprintf("%s:%s", mountID, md.Id)
	migPath := path.Join(mountPrefix, md.Path)

	md.MigId = migID
	md.MigPath = migPath

	return md, nil

}

func (fs *eosStorage) getTargetMetadataPath(mountPrefix, p string) string {
	if strings.HasPrefix(mountPrefix, "/new/user/") {
		return path.Join(strings.TrimPrefix(mountPrefix, "/new/user/"), p)
	}
	return p
}

func (fs *eosStorage) ListFolder(ctx context.Context, p string) ([]*api.Metadata, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts, mountID, mountPrefix, p := fs.getStorageForPath(ctx, p)
	mds, err := ts.ListFolder(ctx, p)
	if err != nil {
		return nil, err
	}

	for _, md := range mds {
		md.Path = fs.getTargetMetadataPath(mountPrefix, md.Path)

		migID := fmt.Sprintf("%s:%s", mountID, md.Id)
		migPath := path.Join(mountPrefix, md.Path)
		md.MigId = migID
		md.MigPath = migPath
	}

	return mds, nil
}

func (fs *eosStorage) CreateDir(ctx context.Context, path string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.CreateDir(ctx, path)
}

func (fs *eosStorage) Delete(ctx context.Context, path string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.Delete(ctx, path)
}

func (fs *eosStorage) Move(ctx context.Context, oldPath, newPath string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, oldPath := fs.getStorageForPath(ctx, oldPath)
	ts, _, _, newPath = fs.getStorageForPath(ctx, newPath)
	return ts.Move(ctx, oldPath, newPath)
}

func (fs *eosStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.Download(ctx, path)
}

func (fs *eosStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.Upload(ctx, path, r)
}

func (fs *eosStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.ListRevisions(ctx, path)
}

func (fs *eosStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.DownloadRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.RestoreRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) EmptyRecycle(ctx context.Context, path string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.EmptyRecycle(ctx, path)
}

func (fs *eosStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts, _, _, path := fs.getStorageForPath(ctx, path)
	return ts.ListRecycle(ctx, path)
}

func (fs *eosStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	// TODO(labkode): get mount/storage from restore key?
	ts, _, _, _ := fs.getStorageForPath(ctx, "")
	return ts.RestoreRecycleEntry(ctx, restoreKey)
}
