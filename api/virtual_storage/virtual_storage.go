package virtual_storage

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/cernbox/reva/api"
	"github.com/gofrs/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

type vfs struct {
	l      *zap.Logger
	mounts []api.Mount
}

func NewVFS(logger *zap.Logger) api.VirtualStorage {
	vfs := new(vfs)
	vfs.l = logger
	vfs.mounts = []api.Mount{}
	return vfs
}

func (v *vfs) ListMounts(ctx context.Context) ([]api.Mount, error) {
	return v.mounts, nil
}

func (v *vfs) AddMount(ctx context.Context, mount api.Mount) error {
	v.l.Debug("new mount point", zap.String("mount", fmt.Sprintf("%+v", mount)))
	if err := validatePath(mount.GetMountPoint()); err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}

	/*
		TODO(labkode): double check
			if mount.GetMountPoint() == "/" {
				err := api.NewError(api.PathInvalidError).WithMessage("mount point cannot be /")
				v.l.Error("", zap.Error(err))
				return err
			}
	*/

	// TODO(labkode): add check for duplicate mounts
	v.mounts = append(v.mounts, mount)
	return nil
}

func (v *vfs) GetMount(p string) (api.Mount, error) {
	// TODO(labkode): if more than 2 matches, check for longest
	p = path.Clean(p)
	if err := validatePath(p); err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}

	for _, m := range v.mounts {
		if strings.HasPrefix(p, m.GetMountPoint()) {
			return m, nil
		}
		if strings.HasPrefix(p, m.GetMountPointId()) {
			return m, nil
		}
	}

	err := api.NewError(api.StorageNotFoundErrorCode).WithMessage(p)
	v.l.Error("", zap.Error(err))
	return nil, err
}

func (v *vfs) RemoveMount(ctx context.Context, mountPoint string) error {
	for i, mount := range v.mounts {
		if mount.GetMountPoint() == mountPoint {
			v.mounts = append(v.mounts[:i], v.mounts[i+1])
		}
	}
	return nil
}

func (v *vfs) GetPathByID(ctx context.Context, id string) (string, error) {
	id = path.Clean(id)
	if !v.isIDPath(id) {
		err := api.NewError(api.PathInvalidError).WithMessage("path is not id-based: " + id)
		v.l.Error("", zap.Error(err))
		return "", err
	}
	m, err := v.GetMount(id)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return "", err
	}
	return m.GetPathByID(ctx, id)
}

func (v *vfs) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return m.SetACL(ctx, derefPath, readOnly, recipient, shareList)

}

func (v *vfs) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return m.UnsetACL(ctx, derefPath, recipient, shareList)
}

func (v *vfs) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return m.UpdateACL(ctx, derefPath, readOnly, recipient, shareList)
}

func (v *vfs) GetQuota(ctx context.Context, path string) (int, int, error) {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return 0, 0, err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return 0, 0, err
	}
	return m.GetQuota(ctx, derefPath)
}

func (v *vfs) CreateDir(ctx context.Context, path string) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return m.CreateDir(ctx, derefPath)
}

func (v *vfs) Delete(ctx context.Context, path string) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return m.Delete(ctx, derefPath)
}

func (v *vfs) Move(ctx context.Context, oldPath, newPath string) error {
	derefOldPath, err := v.getDereferencedPath(ctx, oldPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	derefNewPath, err := v.getDereferencedPath(ctx, newPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}

	//TODO(labkode): handle 3rd party copy between two different mount points
	fromMount, err := v.GetMount(derefOldPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	toMount, err := v.GetMount(derefNewPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	if fromMount.GetMountPoint() == toMount.GetMountPoint() {
		err := fromMount.Move(ctx, derefOldPath, derefNewPath)
		v.l.Error("", zap.Error(err))
		return err
	}

	err = api.NewError(api.StorageNotSupportedErrorCode).WithMessage("inter-mount move not supported")
	v.l.Error("", zap.Error(err))
	return err
}
func (v *vfs) GetMetadata(ctx context.Context, path string) (*api.Metadata, error) {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}

	/*
		if derefPath == "/" {
			return v.inspectRootNode(ctx)
		}
	*/

	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	md, err := m.GetMetadata(ctx, derefPath)
	if err != nil {
		v.l.Error("error getting md", zap.Error(err))
		return nil, err
	}
	return md, nil
}

func (v *vfs) inspectRootNode(ctx context.Context) (*api.Metadata, error) {
	// TODO(labkode): generate the ETAG from concatenation of sorted children etag
	// TODO(labkode): generated the mtime as most recent from childlren
	// TODO(labkode): generate size as sum of sizes from children

	/*
		mds, err := v.listRootNode(ctx)
		if err != nil {
			return nil, err
		}
	*/
	uuid := uuid.Must(uuid.NewV4())
	etag := uuid.String()

	md := &api.Metadata{
		Path:  "/",
		Size:  0,
		Etag:  etag,
		IsDir: true,
		Id:    "root",
	}
	return md, nil
}

func (v *vfs) listRootNode(ctx context.Context) ([]*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	l.Debug("listing vfs root node: /")
	finfos := []*api.Metadata{}
	for _, m := range v.mounts {
		v.l.Debug("visiting mount", zap.String("mount", fmt.Sprintf("%+v", m)))
		finfo, err := v.GetMetadata(ctx, m.GetMountPoint())
		if err != nil {
			// we skip wrong entries from the root node
			v.l.Error("error getting file info for mount", zap.String("path", m.GetMountPoint()), zap.Error(err))
			continue
		}
		finfos = append(finfos, finfo)
	}
	return finfos, nil
}
func (v *vfs) ListFolder(ctx context.Context, p string) ([]*api.Metadata, error) {
	derefPath, err := v.getDereferencedPath(ctx, p)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	/*
		if derefPath == "/" {
			return v.listRootNode(ctx)
		}
	*/

	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}

	mds, err := m.ListFolder(ctx, derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	return mds, nil
}

func (v *vfs) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	err = m.Upload(ctx, derefPath, r)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return nil
}

func (v *vfs) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	l := ctx_zap.Extract(ctx)

	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}

	l.Debug("", zap.String("derefPath", derefPath))
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	r, err := m.Download(ctx, derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err

	}
	return r, nil
}

func (v *vfs) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	revs, err := m.ListRevisions(ctx, derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err

	}
	return revs, nil
}

func (v *vfs) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	r, err := m.DownloadRevision(ctx, derefPath, revisionKey)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	return r, nil
}

func (v *vfs) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	err = m.RestoreRevision(ctx, derefPath, revisionKey)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return nil
}

func (v *vfs) EmptyRecycle(ctx context.Context, path string) error {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	err = m.EmptyRecycle(ctx, derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}
	return nil
}

func (v *vfs) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	derefPath, err := v.getDereferencedPath(ctx, path)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	m, err := v.GetMount(derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	entries, err := m.ListRecycle(ctx, derefPath)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return nil, err
	}
	return entries, nil
}

func (v *vfs) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	m, err := v.GetMount(restoreKey)
	if err != nil {
		v.l.Error("", zap.Error(err))
		return err
	}

	return m.RestoreRecycleEntry(ctx, restoreKey)
}

func validatePath(p string) error {
	if strings.HasPrefix(p, "/") {
		return nil
	}

	// it can be a namespaced path like home:123
	tokens := strings.Split(p, "/")
	if len(tokens) == 0 {
		return api.NewError(api.PathInvalidError).WithMessage("path does not start with / or mount:id")

	}
	// home:123
	mount := tokens[0]
	tokens = strings.Split(mount, ":")
	if len(tokens) < 2 {
		return api.NewError(api.PathInvalidError).WithMessage("path does not start with / or mount:id")

	}
	if tokens[1] == "" {
		return api.NewError(api.PathInvalidError).WithMessage("path does not start with / or mount:id")
	}
	return nil
}

func (v *vfs) isTreePath(path string) bool {
	return strings.HasPrefix(path, "/")
}

// isIDPath checks if the path is id-based, i.e. home:123/docs
func (v *vfs) isIDPath(id string) bool {
	if strings.HasPrefix(id, "/") {
		return false
	}

	tokens := strings.Split(id, ":")
	if len(tokens) < 2 {
		return false

	}
	if tokens[1] == "" {
		return false
	}

	if strings.Contains(tokens[1], "/") {
		return false // is mixed-path
	}

	return true
}

func (v *vfs) isMixedPath(p string) (bool, string, string) {
	if strings.HasPrefix(p, "/") {
		return false, "", ""
	}

	tokens := strings.Split(p, ":")
	if len(tokens) < 2 {
		return false, "", ""

	}
	if tokens[1] == "" {
		return false, "", ""
	}

	otokens := strings.Split(strings.Join(tokens[1:], ":"), "/")
	id := tokens[0] + ":" + otokens[0]

	return true, id, path.Join(otokens[1:]...)
}

func (v *vfs) getDereferencedPath(ctx context.Context, p string) (string, error) {
	p = path.Clean(p)
	if v.isTreePath(p) {
		return p, nil
	}

	if v.isIDPath(p) {
		return v.GetPathByID(ctx, p)
	}

	if ok, id, tail := v.isMixedPath(p); ok {
		derefPath, err := v.GetPathByID(ctx, id)
		if err != nil {
			return "cannot get path by id", err
		}
		return path.Join(derefPath, tail), nil
	}
	err := api.NewError(api.PathInvalidError).WithMessage("path is not tree, id or mixed: " + p)
	v.l.Error("", zap.Error(err))
	return "", err
}
