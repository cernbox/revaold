package storage_homemigration

import (
	"context"
	"fmt"
	"io"

	"github.com/cernbox/reva/api"
	"go.uber.org/zap"
)

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}

type eosStorage struct {
	logger     *zap.Logger
	theStorage api.Storage
}

type Options struct {
	Logger        *zap.Logger
	TargetStorage api.Storage
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
		theStorage: opt.TargetStorage,
	}
	return eosStorage, nil
}

func (fs *eosStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	// we don't support access by fileid on this storage
	return "", api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *eosStorage) getStorageForUser(u *api.User) api.Storage {
	letter := string(u.AccountId[0])
	key := fmt.Sprintf("/eos/user/%s/%s", letter, u.AccountId)

	fs.logger.Debug("migration key", zap.String("key", key))

	return fs.theStorage

}

func (fs *eosStorage) isKeyMigrated(key string) bool {
	return false
}

func (fs *eosStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	ts := fs.getStorageForUser(u)
	return ts.SetACL(ctx, path, readOnly, recipient, shareList)

}

func (fs *eosStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.UnsetACL(ctx, path, recipient, shareList)

}

func (fs *eosStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}

	ts := fs.getStorageForUser(u)
	return ts.UpdateACL(ctx, path, readOnly, recipient, shareList)
}

func (fs *eosStorage) GetMetadata(ctx context.Context, path string) (*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts := fs.getStorageForUser(u)
	return ts.GetMetadata(ctx, path)

}

func (fs *eosStorage) ListFolder(ctx context.Context, path string) ([]*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts := fs.getStorageForUser(u)
	return ts.ListFolder(ctx, path)
}

func (fs *eosStorage) CreateDir(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.CreateDir(ctx, path)
}

func (fs *eosStorage) Delete(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.Delete(ctx, path)
}

func (fs *eosStorage) Move(ctx context.Context, oldPath, newPath string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.Move(ctx, oldPath, newPath)
}

func (fs *eosStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(u)
	return ts.Download(ctx, path)
}

func (fs *eosStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.Upload(ctx, path, r)
}

func (fs *eosStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(u)
	return ts.ListRevisions(ctx, path)
}

func (fs *eosStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(u)
	return ts.DownloadRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.RestoreRevision(ctx, path, revisionKey)
}

func (fs *eosStorage) EmptyRecycle(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.EmptyRecycle(ctx, path)
}

func (fs *eosStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	ts := fs.getStorageForUser(u)
	return ts.ListRecycle(ctx, path)
}

func (fs *eosStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	ts := fs.getStorageForUser(u)
	return ts.RestoreRecycleEntry(ctx, restoreKey)
}
