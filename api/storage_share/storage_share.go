package storage_share

import (
	"context"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/cernbox/reva/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

var shareIDRegexp = regexp.MustCompile(`\(id:.+\)$`)

type shareStorage struct {
	vs           api.VirtualStorage
	shareManager api.ShareManager
	logger       *zap.Logger
}

type Options struct{}

func New(opt *Options, vs api.VirtualStorage, sm api.ShareManager, logger *zap.Logger) api.Storage {
	return &shareStorage{vs, sm, logger}
}

func (fs *shareStorage) getReceivedShare(ctx context.Context, name string) (*api.FolderShare, string, error) {
	// path is /016633a5-22d0-478c-a148-be3000f15d62/Photos/Test
	fs.logger.Debug("get received share for path", zap.String("path", name))

	items := strings.Split(name, "/")
	if len(items) < 2 {
		return nil, "", api.NewError(api.StorageNotFoundErrorCode)
	}

	id := items[1]
	share, err := fs.shareManager.GetReceivedFolderShare(ctx, id)
	if err != nil {
		return nil, "", err
	}

	var relativePath string
	if len(items) > 2 {
		relativePath = path.Join(items[2:]...)
	}

	fs.logger.Debug("resolve received share path", zap.String("path", name), zap.String("relativepath", relativePath), zap.String("sharepath", share.Path), zap.String("share_id", share.Id))
	return share, relativePath, nil
}

func (fs *shareStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	path := "/" + id
	_, _, err := fs.getReceivedShare(ctx, path)
	if err != nil {
		return "", err
	}
	return path, nil
}

func (fs *shareStorage) getReceivedShareMetadata(ctx context.Context, share *api.FolderShare) (*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	finfo, err := fs.vs.GetMetadata(ctx, share.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	if !finfo.IsReadOnly {
		finfo.IsReadOnly = share.ReadOnly
	}

	finfo.ShareTarget = share.Target
	finfo.IsShareable = false // TODO(labkode): add re-shares
	return finfo, nil
}

func (fs *shareStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
func (fs *shareStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	if p == "/" {
		return &api.Metadata{
			Path:  "/",
			Size:  0,
			Etag:  "TODO",
			Mtime: 0,
			IsDir: true,
		}, nil
	}

	share, shareRelativePath, err := fs.getReceivedShare(ctx, p)
	if err != nil {
		return nil, err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	shareMetadata, err := fs.getReceivedShareMetadata(newCtx, share)
	if err != nil {
		return nil, err
	}

	internalPath := path.Join(share.Path, shareRelativePath)
	md, err := fs.vs.GetMetadata(newCtx, internalPath)
	if err != nil {
		return nil, err
	}

	md.IsReadOnly = shareMetadata.IsReadOnly
	md.Path = path.Join("/", share.Id, strings.TrimPrefix(md.Path, shareMetadata.Path))
	md.Id = share.Id
	md.ShareTarget = shareMetadata.ShareTarget
	md.IsShareable = shareMetadata.IsShareable
	return md, nil
}

func (fs *shareStorage) listRoot(ctx context.Context) ([]*api.Metadata, error) {
	shares, err := fs.shareManager.ListReceivedShares(ctx)
	if err != nil {
		return nil, err
	}

	finfos := []*api.Metadata{}
	for _, share := range shares {
		p := path.Join("/", share.Id)
		fi, err := fs.GetMetadata(ctx, p)
		if err != nil {
			return nil, err
		}
		finfos = append(finfos, fi)
	}
	return finfos, nil

}

// name is /<share_id>/a/b/c
func (fs *shareStorage) ListFolder(ctx context.Context, name string) ([]*api.Metadata, error) {
	if name == "/" {
		return fs.listRoot(ctx)
	}

	share, shareRelativePath, err := fs.getReceivedShare(ctx, name)
	if err != nil {
		return nil, err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	shareMetadata, err := fs.getReceivedShareMetadata(newCtx, share)
	if err != nil {
		return nil, err
	}

	targetPath := path.Join(shareMetadata.Path, shareRelativePath)
	mds, err := fs.vs.ListFolder(newCtx, targetPath)
	if err != nil {
		return nil, err
	}
	for _, md := range mds {
		originalPath := md.Path
		p := path.Join(share.Id, strings.TrimPrefix(md.Path, shareMetadata.Path))
		md.Path = path.Join("/", p)
		md.Id = p
		md.ShareTarget = shareMetadata.ShareTarget
		md.IsReadOnly = shareMetadata.IsReadOnly
		md.IsShareable = shareMetadata.IsShareable
		fs.logger.Debug("children entry", zap.String("childpath", md.Path), zap.String("originalchildmd.path", originalPath), zap.String("childmd.path", md.Path), zap.String("parentmd.path", shareMetadata.Path), zap.String("strings", strings.TrimPrefix(originalPath, shareMetadata.Path)))
	}

	return mds, nil
}

func (fs *shareStorage) Download(ctx context.Context, name string) (io.ReadCloser, error) {
	share, p, err := fs.getReceivedShare(ctx, name)
	if err != nil {
		return nil, err
	}

	p = path.Join(share.Path, p)
	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	return fs.vs.Download(newCtx, p)
}

func (fs *shareStorage) Upload(ctx context.Context, name string, r io.ReadCloser) error {
	share, p, err := fs.getReceivedShare(ctx, name)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	p = path.Join(share.Path, p)
	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	return fs.vs.Upload(newCtx, p, r)
}

func (fs *shareStorage) Move(ctx context.Context, oldName, newName string) error {
	oldShare, oldPath, err := fs.getReceivedShare(ctx, oldName)
	if err != nil {
		return err
	}
	newShare, newPath, err := fs.getReceivedShare(ctx, newName)
	if err != nil {
		return err
	}

	if oldShare.ReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	if oldShare.Id != newShare.Id {
		return errors.New("cross-share rename forbidden")
	}

	oldPath = path.Join(oldShare.Path, oldPath)
	newPath = path.Join(newShare.Path, newPath)
	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: oldShare.OwnerId})
	return fs.vs.Move(newCtx, oldPath, newPath)
}

func (fs *shareStorage) GetQuota(ctx context.Context, name string) (int, int, error) {
	share, p, err := fs.getReceivedShare(ctx, name)
	if err != nil {
		return 0, 0, err
	}

	p = path.Join(share.Path, p)
	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	return fs.vs.GetQuota(newCtx, p)

}
func (fs *shareStorage) CreateDir(ctx context.Context, name string) error {
	share, p, err := fs.getReceivedShare(ctx, name)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	p = path.Join(share.Path, p)
	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	return fs.vs.CreateDir(newCtx, p)
}

func (fs *shareStorage) Delete(ctx context.Context, name string) error {
	share, p, err := fs.getReceivedShare(ctx, name)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	p = path.Join(share.Path, p)
	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: share.OwnerId})
	return fs.vs.Delete(newCtx, p)
}

func (fs *shareStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) EmptyRecycle(ctx context.Context, path string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *shareStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
