package storage_public_link

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/cernbox/reva/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

type linkStorage struct {
	vfs         api.VirtualStorage
	linkManager api.PublicLinkManager
	logger      *zap.Logger
}

type Options struct {
}

func New(opt *Options, vfs api.VirtualStorage, lm api.PublicLinkManager, logger *zap.Logger) api.Storage {
	return &linkStorage{vfs, lm, logger}
}

func getPublicLinkFromContext(ctx context.Context) (*api.PublicLink, error) {
	pl, ok := api.ContextGetPublicLink(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return pl, nil
}
func (fs *linkStorage) getLink(ctx context.Context, name string) (*api.PublicLink, string, context.Context, error) {
	// path is /016633a5-22d0-478c-a148-be3000f15d62/Photos/Test
	fs.logger.Debug("get link for path", zap.String("path", name))

	items := strings.Split(name, "/")
	if len(items) < 2 {
		return nil, "", nil, api.NewError(api.StorageNotFoundErrorCode)
	}
	token := items[1]

	pl, err := getPublicLinkFromContext(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	if token != pl.Token {
		return nil, "", nil, api.NewError(api.ContextUserRequiredError).WithMessage("pl access token does not match requested path")
	}

	//ctx = api.ContextSetUser(ctx, &api.User{AccountId: pl.OwnerId, Groups: []string{}})

	link, err := fs.linkManager.InspectPublicLinkByToken(ctx, token)
	if err != nil {
		return nil, "", nil, err
	}

	var relativePath string
	if len(items) > 2 {
		relativePath = path.Join(items[2:]...)
	}

	fs.logger.Debug("resolve link path", zap.String("path", name), zap.String("relativepath", relativePath), zap.String("linkpath", link.Path), zap.String("linktoken", link.Token))
	return link, relativePath, ctx, nil
}

func (fs *linkStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	path := "/" + id
	_, _, ctx, err := fs.getLink(ctx, path)
	if err != nil {
		return "", err
	}
	return path, nil
}

func (fs *linkStorage) getLinkMetadata(ctx context.Context, link *api.PublicLink) (*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	finfo, err := fs.vfs.GetMetadata(ctx, link.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	if !finfo.IsReadOnly {
		finfo.IsReadOnly = link.ReadOnly
	}

	finfo.IsShareable = false // TODO(labkode: add re-shares
	return finfo, nil
}

func (fs *linkStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
func (fs *linkStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	if p == "/" {
		return &api.Metadata{
			Path:  "/",
			Size:  0,
			Etag:  "TODO",
			Mtime: 0,
			IsDir: true,
		}, nil
	}
	link, linkRelativePath, ctx, err := fs.getLink(ctx, p)
	if err != nil {
		return nil, err
	}

	linkMetadata, err := fs.getLinkMetadata(ctx, link)
	if err != nil {
		return nil, err
	}

	internalPath := path.Join(link.Path, linkRelativePath)
	md, err := fs.vfs.GetMetadata(ctx, internalPath)
	if err != nil {
		return nil, err
	}

	md.IsReadOnly = linkMetadata.IsReadOnly
	md.Path = path.Join("/", link.Token, strings.TrimPrefix(md.Path, linkMetadata.Path))
	md.Id = link.Token
	md.IsShareable = linkMetadata.IsShareable
	return md, nil
}

func (fs *linkStorage) listRoot(ctx context.Context) ([]*api.Metadata, error) {
	links, err := fs.linkManager.ListPublicLinks(ctx, "")
	if err != nil {
		return nil, err
	}
	finfos := []*api.Metadata{}
	for _, link := range links {
		fi, err := fs.vfs.GetMetadata(ctx, link.Path)
		if err != nil {
			return nil, err
		}
		fi.Path = "/" + link.Token
		fi.Id = link.Token
		finfos = append(finfos, fi)
	}
	return finfos, nil

}

// name is /<token>/a/b/c
func (fs *linkStorage) ListFolder(ctx context.Context, name string) ([]*api.Metadata, error) {
	if name == "/" {
		return fs.listRoot(ctx)
	}

	link, linkRelativePath, ctx, err := fs.getLink(ctx, name)
	if err != nil {
		return nil, err
	}

	linkMetadata, err := fs.getLinkMetadata(ctx, link)
	if err != nil {
		return nil, err
	}

	targetPath := path.Join(linkMetadata.Path, linkRelativePath)
	mds, err := fs.vfs.ListFolder(ctx, targetPath)
	if err != nil {
		return nil, err
	}
	for _, md := range mds {
		originalPath := md.Path
		p := path.Join(link.Token, strings.TrimPrefix(md.Path, linkMetadata.Path))
		md.Path = path.Join("/", p)
		md.IsReadOnly = linkMetadata.IsReadOnly
		md.Id = p
		md.IsShareable = linkMetadata.IsShareable
		fs.logger.Debug("children entry", zap.String("childpath", md.Path), zap.String("originalchildmd.path", originalPath), zap.String("childmd.path", md.Path), zap.String("parentmd.path", linkMetadata.Path), zap.String("strings", strings.TrimPrefix(originalPath, linkMetadata.Path)))
	}

	return mds, nil
}

func (fs *linkStorage) Download(ctx context.Context, name string) (io.ReadCloser, error) {
	link, p, ctx, err := fs.getLink(ctx, name)
	if err != nil {
		return nil, err
	}

	p = path.Join(link.Path, p)
	return fs.vfs.Download(ctx, p)
}

func (fs *linkStorage) Upload(ctx context.Context, name string, r io.ReadCloser) error {
	link, p, ctx, err := fs.getLink(ctx, name)
	if err != nil {
		return err
	}

	p = path.Join(link.Path, p)
	return fs.vfs.Upload(ctx, p, r)
}

func (fs *linkStorage) Move(ctx context.Context, oldName, newName string) error {
	oldLink, oldPath, ctx, err := fs.getLink(ctx, oldName)
	if err != nil {
		return err
	}
	newLink, newPath, ctx, err := fs.getLink(ctx, newName)
	if err != nil {
		return err
	}
	if oldLink.Token != newLink.Token {
		return errors.New("cross-link rename forbidden")
	}

	oldPath = path.Join(oldLink.Path, oldPath)
	newPath = path.Join(newLink.Path, newPath)
	return fs.vfs.Move(ctx, oldPath, newPath)
}

func (fs *linkStorage) GetQuota(ctx context.Context, name string) (int, int, error) {
	link, p, ctx, err := fs.getLink(ctx, name)
	if err != nil {
		return 0, 0, err
	}

	p = path.Join(link.Path, p)
	return fs.vfs.GetQuota(ctx, p)
}

func (fs *linkStorage) CreateDir(ctx context.Context, name string) error {
	link, p, ctx, err := fs.getLink(ctx, name)
	if err != nil {
		return err
	}

	p = path.Join(link.Path, p)
	return fs.vfs.CreateDir(ctx, p)
}

func (fs *linkStorage) Delete(ctx context.Context, name string) error {
	link, p, ctx, err := fs.getLink(ctx, name)
	if err != nil {
		return err
	}

	p = path.Join(link.Path, p)
	return fs.vfs.Delete(ctx, p)
}

func (fs *linkStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) EmptyRecycle(ctx context.Context, path string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *linkStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
