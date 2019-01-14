package mount

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/cernbox/revaold/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

// New will return a new mount with specific mount options.
func New(mountID, mountPoint string, opts *api.MountOptions, s api.Storage) api.Mount {
	mountPoint = path.Clean(mountPoint)
	if mountPoint != "/" {
		mountPoint = strings.TrimSuffix(mountPoint, "/")
	}

	if opts == nil {
		opts = &api.MountOptions{}
	}

	m := &mount{storage: s,
		mountPoint:   mountPoint,
		mountOptions: opts,
	}
	m.mountPointId = mountID + ":"
	return m
}

type mount struct {
	storage      api.Storage
	mountPoint   string
	mountPointId string
	mountOptions *api.MountOptions
	logger       *zap.Logger
}

func (m *mount) isReadOnly() bool {
	return m.mountOptions.ReadOnly
}

func (m *mount) isSharingEnabled() bool {
	if m.isReadOnly() {
		return false
	}
	return !m.mountOptions.SharingDisabled
}

func (m *mount) GetMountPoint() string              { return m.mountPoint }
func (m *mount) GetMountPointId() string            { return m.mountPointId }
func (m *mount) GetMountOptions() *api.MountOptions { return m.mountOptions }
func (m *mount) GetStorage() api.Storage            { return m.storage }

func (m *mount) GetQuota(ctx context.Context, path string) (int, int, error) {
	p, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	return m.storage.GetQuota(ctx, p)
}

func (m *mount) GetPathByID(ctx context.Context, id string) (string, error) {
	id, err := m.getInternalIDPath(ctx, id)
	if err != nil {
		return "", err
	}
	p, err := m.storage.GetPathByID(ctx, id)
	if err != nil {
		return "", err
	}
	return path.Join(m.GetMountPoint(), p), nil
}

func (m *mount) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	if !m.isSharingEnabled() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("sharing-disabled mount")
	}
	p, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.SetACL(ctx, p, readOnly, recipient, shareList)
}

func (m *mount) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	if !m.isSharingEnabled() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("sharing-disabled mount")
	}
	p, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.UpdateACL(ctx, p, readOnly, recipient, shareList)
}

func (m *mount) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	if !m.isSharingEnabled() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("sharing-disabled mount")
	}
	p, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.UnsetACL(ctx, p, recipient, shareList)
}

func (m *mount) CreateDir(ctx context.Context, path string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	p, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.CreateDir(ctx, p)
}

func (m *mount) Delete(ctx context.Context, path string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	p, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.Delete(ctx, p)
}

func (m *mount) Move(ctx context.Context, oldPath, newPath string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	op, _, err := m.getInternalPath(ctx, oldPath)
	if err != nil {
		return err
	}
	np, _, err := m.getInternalPath(ctx, newPath)
	if err != nil {
		return err
	}
	return m.storage.Move(ctx, op, np)
}
func (m *mount) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	l.Debug("GetMetadata", zap.String("path", p))

	internalPath, mountPrefix, err := m.getInternalPath(ctx, p)
	if err != nil {
		return nil, err
	}

	fi, err := m.storage.GetMetadata(ctx, internalPath)
	if err != nil {
		return nil, err
	}

	internalPath = path.Clean(fi.Path)
	fi.Path = path.Join(mountPrefix, internalPath)
	l.Debug("path conversion: internal => external", zap.String("external", fi.Path), zap.String("internal", internalPath))
	fi.Id = m.GetMountPointId() + fi.Id
	if fi.IsShareable {
		fi.IsShareable = m.isSharingEnabled()
	}
	if !fi.IsReadOnly {
		fi.IsReadOnly = m.isReadOnly()
	}

	return fi, nil
}

func (m *mount) ListFolder(ctx context.Context, p string) ([]*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	l.Debug("ListFolder", zap.String("path", p))

	internalPath, mountPrefix, err := m.getInternalPath(ctx, p)
	if err != nil {
		return nil, err
	}

	finfos, err := m.storage.ListFolder(ctx, internalPath)
	if err != nil {
		return nil, err
	}

	for _, f := range finfos {
		if f.DerefPath != "" {
			f.DerefPath = path.Join(m.GetMountPoint(), path.Clean(f.DerefPath))
		}
		internalPath := path.Clean(f.Path)
		// add mount prefix
		f.Path = path.Join(mountPrefix, internalPath)
		l.Debug("path conversion: internal => external", zap.String("external", f.Path), zap.String("internal", internalPath))
		f.Id = m.GetMountPointId() + f.Id
		if f.IsShareable {
			f.IsShareable = m.isSharingEnabled()
		}
		if !f.IsReadOnly {
			f.IsReadOnly = m.isReadOnly()
		}
	}

	return finfos, nil
}

func (m *mount) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	internalPath, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.Upload(ctx, internalPath, r)
}

func (m *mount) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	internalPath, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return nil, err
	}
	return m.storage.Download(ctx, internalPath)
}

func (m *mount) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	internalPath, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return nil, err
	}
	return m.storage.ListRevisions(ctx, internalPath)
}

func (m *mount) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	internalPath, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return nil, err
	}
	return m.storage.DownloadRevision(ctx, internalPath, revisionKey)
}

func (m *mount) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	internalPath, _, err := m.getInternalPath(ctx, path)
	if err != nil {
		return err
	}
	return m.storage.RestoreRevision(ctx, internalPath, revisionKey)
}

func (m *mount) EmptyRecycle(ctx context.Context, path string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	return m.storage.EmptyRecycle(ctx, path)
}

func (m *mount) ListRecycle(ctx context.Context, p string) ([]*api.RecycleEntry, error) {
	entries, err := m.storage.ListRecycle(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		e.RestoreKey = fmt.Sprintf("%s%s", m.mountPointId, e.RestoreKey)
		e.RestorePath = path.Join(m.mountPoint, e.RestorePath)
	}
	return entries, nil
}

func (m *mount) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	internalRestoreKey, err := m.getInternalRestoreKey(ctx, restoreKey)
	if err != nil {
		return err
	}
	return m.storage.RestoreRecycleEntry(ctx, internalRestoreKey)
}

func (m *mount) getInternalIDPath(ctx context.Context, p string) (string, error) {
	// home:387/docs
	tokens := strings.Split(p, "/")
	if len(tokens) != 1 {
		return "", api.NewError(api.PathInvalidError).WithMessage("path is not id-based: " + p)
	}
	mount := tokens[0]
	if mount == "" {
		return "", api.NewError(api.PathInvalidError).WithMessage("path is not id-based: " + p)
	}

	tokens = strings.Split(mount, ":")
	if len(tokens) != 2 {
		return "", api.NewError(api.PathInvalidError).WithMessage("path is not id-based: " + p)
	}
	return tokens[1], nil
}

func (m *mount) getInternalRestoreKey(ctx context.Context, restoreKey string) (string, error) {
	l := ctx_zap.Extract(ctx)
	if strings.HasPrefix(restoreKey, m.mountPointId) {
		internalRestoreKey := strings.TrimPrefix(restoreKey, m.mountPointId)
		l.Debug("restore key conversion: external => internal", zap.String("external", restoreKey), zap.String("internal", internalRestoreKey))
		return internalRestoreKey, nil
	}
	return "", api.NewError(api.PathInvalidError).WithMessage("invalid  restore key for this mount")

}
func (m *mount) getInternalPath(ctx context.Context, p string) (string, string, error) {
	l := ctx_zap.Extract(ctx)
	if strings.HasPrefix(p, m.mountPoint) {
		internalPath := path.Join("/", strings.TrimPrefix(p, m.mountPoint))
		l.Debug("path conversion: external => internal", zap.String("external", p), zap.String("internal", internalPath), zap.String("mount", m.mountPoint))
		return internalPath, m.mountPoint, nil
	}
	return "", "", api.NewError(api.PathInvalidError).WithMessage("invalid path for this mount. mountpoint:" + m.mountPoint + " path:" + p)
}
