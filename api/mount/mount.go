package mount

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"gitlab.com/labkode/reva/api"
	"go.uber.org/zap"
)

// New will return a new mount with specific mount options.
func New(s api.Storage, mountPoint string, options ...api.MountOption) api.Mount {
	m := &mount{storage: s,
		mountPoint:   strings.TrimSuffix(mountPoint, "/"),
		mountOptions: options,
	}
	m.mountPointId = strings.TrimPrefix(mountPoint, "/") + ":"
	return m
}

type mount struct {
	storage      api.Storage
	mountPoint   string
	mountPointId string
	mountOptions []api.MountOption
	logger       *zap.Logger
}

func (m *mount) isReadOnly() bool {
	for _, m := range m.mountOptions {
		if m == api.MountOptionReadOnly {
			return true
		}
	}
	return false
}

func (m *mount) GetMountPoint() string              { return m.mountPoint }
func (m *mount) GetMountPointId() string            { return m.mountPointId }
func (m *mount) GetMountOptions() []api.MountOption { return m.mountOptions }

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
	return m.Download(ctx, internalPath)
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

func (m *mount) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	entries, err := m.storage.ListRecycle(ctx, path)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		e.RestoreKey = fmt.Sprintf("%s:%s", m.mountPointId, e.RestoreKey)
	}
	return entries, nil
}

func (m *mount) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	if m.isReadOnly() {
		return api.NewError(api.StoragePermissionDeniedErrorCode).WithMessage("read-only mount")
	}
	internalRestoreKey, _, err := m.getInternalPath(ctx, restoreKey)
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
func (m *mount) getInternalPath(ctx context.Context, p string) (string, string, error) {
	l := ctx_zap.Extract(ctx)
	if strings.HasPrefix(p, m.mountPoint) {
		internalPath := path.Join("/", strings.TrimPrefix(p, m.mountPoint))
		l.Debug("path conversion: external => internal", zap.String("external", p), zap.String("internal", internalPath))
		return internalPath, m.mountPoint, nil
	}
	return "", "", api.NewError(api.PathInvalidError).WithMessage("invalid path for this mount")
}
