package storage_homemigration

import (
	"context"
	"fmt"
	"io"

	"github.com/cernbox/reva/api"
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

	oldHome    api.Storage
	newHomeMap map[string]api.Storage
}

type Options struct {
	Logger   *zap.Logger
	Migrator cbox_api.Migrator

	OldHome    api.Storage
	NewHomeMap map[string]api.Storage
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
		oldHome:    opt.OldHome,
		newHomeMap: opt.NewHomeMap,
		migrator:   opt.Migrator,
	}
	return eosStorage, nil
}

func (fs *eosStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	return id, nil
	// we don't support access by fileid on this storage
	return "", api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *eosStorage) getStorageForLetter(ctx context.Context, letter string) api.Storage {
	s, ok := fs.newHomeMap[letter]
	if !ok {
		panic("storage not found for letter: " + letter)
	}
	return s
}

func (fs *eosStorage) getStorageForUser(ctx context.Context, u *api.User) api.Storage {
	username := u.AccountId
	letter := string(username[0])
	key := fmt.Sprintf("/eos/user/%s/%s", letter, u.AccountId)
	fs.logger.Debug("migration key", zap.String("key", key))

	ok, err := fs.migrator.IsPathMigrated(ctx, key, username)
	if err != nil {
		fs.logger.Error("error calling migrator", zap.Error(err))
		panic(err)
	}

	if !ok { // user has not been migrated or is a new user
		fs.logger.Info("forwarding user to old_home", zap.String("username", username))
		return fs.oldHome
	}

	s := fs.getStorageForLetter(ctx, letter)
	fs.logger.Info("forwarding user to new_home", zap.String("username", username))
	return s
}

func (fs *eosStorage) isKeyMigrated(key string) bool {
	return false
}

func (fs *eosStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	ts := fs.getStorageForUser(ctx, u)
	return ts.SetACL(ctx, path, readOnly, recipient, shareList)

}

func (fs *eosStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.UnsetACL(ctx, path, recipient, shareList)

}

func (fs *eosStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	ts := fs.getStorageForUser(ctx, u)
	return ts.UpdateACL(ctx, path, readOnly, recipient, shareList)
}

func (fs *eosStorage) GetMetadata(ctx context.Context, path string) (*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts := fs.getStorageForUser(ctx, u)
	return ts.GetMetadata(ctx, path)

}

func (fs *eosStorage) ListFolder(ctx context.Context, path string) ([]*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts := fs.getStorageForUser(ctx, u)
	return ts.ListFolder(ctx, path)
}

func (fs *eosStorage) CreateDir(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.CreateDir(ctx, path)
}

func (fs *eosStorage) Delete(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.Delete(ctx, path)
}

func (fs *eosStorage) Move(ctx context.Context, oldPath, newPath string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.Move(ctx, oldPath, newPath)
}

func (fs *eosStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.Download(ctx, path)
}

func (fs *eosStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.Upload(ctx, path, r)
}

func (fs *eosStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.ListRevisions(ctx, path)
}

func (fs *eosStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.DownloadRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.RestoreRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) EmptyRecycle(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.EmptyRecycle(ctx, path)
}

func (fs *eosStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.ListRecycle(ctx, path)
}

func (fs *eosStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(ctx, u)
	return ts.RestoreRecycleEntry(ctx, restoreKey)
}
