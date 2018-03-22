package homefs

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
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

type homeStorage struct {
	wrappedStorage api.Storage
}

func New(wrappedStorage api.Storage) api.Storage {
	return &homeStorage{wrappedStorage: wrappedStorage}
}

func (fs *homeStorage) getHomePath(ctx context.Context, user *api.User) string {
	return fmt.Sprintf("/%s/%s", string(user.AccountId[0]), user.AccountId)
}
func (fs *homeStorage) getInternalPath(ctx context.Context, user *api.User, p string) string {
	l := ctx_zap.Extract(ctx)
	homePath := fs.getHomePath(ctx, user)
	internalPath := path.Join(homePath, p)
	l.Debug("path conversion: external => internal", zap.String("external", p), zap.String("internal", internalPath))
	return internalPath
}

func (fs *homeStorage) removeNamespace(ctx context.Context, user *api.User, np string) string {
	l := ctx_zap.Extract(ctx)
	homePath := fs.getHomePath(ctx, user)
	p := strings.TrimPrefix(np, homePath)
	if p == "" {
		p = "/"
	}
	l.Debug("path conversion: internal => external", zap.String("internal", np), zap.String("external", p))
	return p
}

func (fs *homeStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return "", err
	}
	path, err := fs.wrappedStorage.GetPathByID(ctx, id)
	if err != nil {
		return "", err
	}
	return fs.removeNamespace(ctx, u, path), nil

}

func (fs *homeStorage) GetMetadata(ctx context.Context, path string) (*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = fs.getInternalPath(ctx, u, path)
	md, err := fs.wrappedStorage.GetMetadata(ctx, path)
	if err != nil {
		return nil, err
	}
	md.Path = fs.removeNamespace(ctx, u, md.Path)
	return md, nil
}

func (fs *homeStorage) ListFolder(ctx context.Context, path string) ([]*api.Metadata, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = fs.getInternalPath(ctx, u, path)
	mds, err := fs.wrappedStorage.ListFolder(ctx, path)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(mds); i++ {
		mds[i].Path = fs.removeNamespace(ctx, u, mds[i].Path)
	}
	return mds, nil
}

func (fs *homeStorage) CreateDir(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.CreateDir(ctx, path)
}

func (fs *homeStorage) Delete(ctx context.Context, path string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.Delete(ctx, path)
}

func (fs *homeStorage) Move(ctx context.Context, oldPath, newPath string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	oldPath = fs.getInternalPath(ctx, u, oldPath)
	newPath = fs.getInternalPath(ctx, u, newPath)
	return fs.wrappedStorage.Move(ctx, oldPath, newPath)
}

func (fs *homeStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.Download(ctx, path)
}

func (fs *homeStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.Upload(ctx, path, r)
}

func (fs *homeStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.ListRevisions(ctx, path)
}

func (fs *homeStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.DownloadRevision(ctx, path, revisionKey)
}

func (fs *homeStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.RestoreRevision(ctx, path, revisionKey)
}

func (fs *homeStorage) EmptyRecycle(ctx context.Context, path string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	return fs.wrappedStorage.EmptyRecycle(ctx, path)
}

func (fs *homeStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := fs.wrappedStorage.ListRecycle(ctx, path)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(entries); i++ {
		entries[i].RestorePath = fs.removeNamespace(ctx, u, entries[i].RestorePath)
	}
	return entries, nil
}

func (fs *homeStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	_, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	return fs.wrappedStorage.RestoreRecycleEntry(ctx, restoreKey)
}
