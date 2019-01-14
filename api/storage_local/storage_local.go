package storage_local

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/cernbox/revaold/api"

	"go.uber.org/zap"
)

type Options struct {
	// Namespace for path operations
	Namespace string `json:"namespace"`

	Logger *zap.Logger
}

func (opt *Options) init() {
	if opt.Logger == nil {
		opt.Logger, _ = zap.NewProduction()
	}
	opt.Namespace = path.Clean(opt.Namespace)
	if !strings.HasPrefix(opt.Namespace, "/") {
		opt.Namespace = "/"
	}
}

func New(opt *Options) api.Storage {
	opt.init()
	s := new(localStorage)
	s.namespace = opt.Namespace
	s.logger = opt.Logger
	return s
}

func (fs *localStorage) addNamespace(p string) string {
	np := path.Join(fs.namespace, p)
	fs.logger.Debug("add namespace", zap.String("path", p), zap.String("npath", np))
	return np
}

func (fs *localStorage) removeNamespace(np string) string {
	p := strings.TrimPrefix(np, fs.namespace)
	if p == "" {
		p = "/"
	}
	fs.logger.Debug("remove namespace", zap.String("npath", np), zap.String("path", p))
	return p
}

type localStorage struct {
	namespace string
	logger    *zap.Logger
}

func (fs *localStorage) convertToFileInfoWithNamespace(osFileInfo os.FileInfo, np string) *api.Metadata {
	fi := &api.Metadata{}
	fi.IsDir = osFileInfo.IsDir()
	fi.Path = fs.removeNamespace(path.Join("/", np))
	fi.Size = uint64(osFileInfo.Size())
	fi.Id = fi.Path
	fi.Etag = fmt.Sprintf("%d", osFileInfo.ModTime().Unix())
	return fi
}

func (fs *localStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	return "", api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
func (fs *localStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) GetQuota(ctx context.Context, name string) (int, int, error) {
	// TODO(labkode): add quota check
	return 0, 0, nil
}

func (fs *localStorage) CreateDir(ctx context.Context, name string) error {
	name = fs.addNamespace(name)
	return os.Mkdir(name, 0644)
}

func (fs *localStorage) Delete(ctx context.Context, name string) error {
	name = fs.addNamespace(name)
	err := os.Remove(name)
	if err != nil {
		if os.IsNotExist(err) {
			return api.NewError(api.StorageNotFoundErrorCode)
		}
		return err
	}
	return nil
}

func (fs *localStorage) Move(ctx context.Context, oldName, newName string) error {
	oldName = fs.addNamespace(oldName)
	newName = fs.addNamespace(newName)
	return os.Rename(oldName, newName)
}

func (fs *localStorage) GetMetadata(ctx context.Context, name string) (*api.Metadata, error) {
	name = fs.addNamespace(name)
	osFileInfo, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, api.NewError(api.StorageNotFoundErrorCode).WithMessage(err.Error())
		}
		return nil, err
	}
	return fs.convertToFileInfoWithNamespace(osFileInfo, name), nil
}

func (fs *localStorage) ListFolder(ctx context.Context, name string) ([]*api.Metadata, error) {
	name = fs.addNamespace(name)
	osFileInfos, err := ioutil.ReadDir(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, api.NewError(api.StorageNotFoundErrorCode).WithMessage(err.Error())
		}
		return nil, err
	}
	finfos := []*api.Metadata{}
	for _, osFileInfo := range osFileInfos {
		finfos = append(finfos, fs.convertToFileInfoWithNamespace(osFileInfo, path.Join(name, osFileInfo.Name())))
	}
	return finfos, nil
}

func (fs *localStorage) Upload(ctx context.Context, name string, r io.ReadCloser) error {
	name = fs.addNamespace(name)
	// we cannot rely on /tmp as it can live in another partition and we can
	// hit invalid cross-device link errors, so we create the tmp file in the same directory and the file
	// is supposed to be written.
	tmp, err := ioutil.TempFile(path.Dir(name), ".alustotmp-")
	if err != nil {
		return err
	}
	_, err = io.Copy(tmp, r)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), name); err != nil {
		if os.IsNotExist(err) {
			return api.NewError(api.StorageNotFoundErrorCode)
		}
		return err
	}
	return nil
}

func (fs *localStorage) Download(ctx context.Context, name string) (io.ReadCloser, error) {
	name = fs.addNamespace(name)
	r, err := os.Open(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, api.NewError(api.StorageNotFoundErrorCode)
		}
	}
	return r, nil
}

func (fs *localStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) EmptyRecycle(ctx context.Context, path string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
