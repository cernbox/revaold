package nopstorage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"strings"
	"time"

	"github.com/cernbox/reva/api"
)

type nopStorage struct {
	fileInfos []*api.Metadata
}

type Options struct {
	Metadatas []*api.Metadata
}

func (opt *Options) init() {
	if opt.Metadatas == nil {
		opt.Metadatas = []*api.Metadata{}
	}
}

func New(opt *Options) api.Storage {
	opt.init()
	nopStorage := new(nopStorage)
	nopStorage.fileInfos = opt.Metadatas
	return nopStorage
}

func (fs *nopStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	return "", api.NewError(api.StorageNotSupportedErrorCode)

}

func (fs *nopStorage) GetMetadata(ctx context.Context, path string, deref bool) (*api.Metadata, error) {
	for _, fi := range fs.fileInfos {
		if fi.Path == path {
			return fi, nil
		}
	}
	return nil, api.NewError(api.StorageNotFoundErrorCode)
}

func (fs *nopStorage) ListFolder(ctx context.Context, p string, deref bool) ([]*api.Metadata, error) {
	finfos := []*api.Metadata{}
	for _, fi := range fs.fileInfos {
		dir, _ := path.Split(fi.Path)
		if strings.TrimSuffix(dir, "/") == p {
			finfos = append(finfos, fi)
		}
	}
	return finfos, nil
}

func (fs *nopStorage) CreateDir(ctx context.Context, path string) error {
	finfo := new(api.Metadata)
	finfo.Path = path
	finfo.Size = uint64(0)
	finfo.Mtime = uint64(time.Now().Unix())
	finfo.IsDir = true
	fs.fileInfos = append(fs.fileInfos, finfo)
	return nil
}

func (fs *nopStorage) Delete(ctx context.Context, path string) error {
	for index, fi := range fs.fileInfos {
		if fi.Path == path {
			fs.fileInfos = append(fs.fileInfos[:index], fs.fileInfos[index+1])
			return nil
		}
	}
	return api.NewError(api.StorageNotFoundErrorCode)
}

func (fs *nopStorage) findMetadata(path string) (*api.Metadata, int, error) {
	for index, fi := range fs.fileInfos {
		if fi.Path == path {
			return fi, index, nil
		}
	}
	return nil, 0, api.NewError(api.StorageNotFoundErrorCode)
}
func (fs *nopStorage) Move(ctx context.Context, oldPath, newPath string) error {
	oldMetadata, _, err := fs.findMetadata(oldPath)
	if err != nil {
		return err
	}

	_, _, err = fs.findMetadata(newPath)
	if err == nil {
		return api.NewError(api.StorageAlreadyExistsErrorCode)
	}

	oldMetadata.Path = newPath
	fs.Delete(ctx, oldPath)
	fs.fileInfos = append(fs.fileInfos, oldMetadata)
	return nil

}

func (fs *nopStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	finfo, _, err := fs.findMetadata(path)
	if err != nil {
		return nil, err
	}
	b := ioutil.NopCloser(bytes.NewBufferString(fmt.Sprintf("Contents: %s", finfo.Path)))
	return b, nil
}

func (fs *nopStorage) Upload(ctx context.Context, path string, r io.ReadCloser) error {
	return nil
}

func (fs *nopStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *nopStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *nopStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *nopStorage) EmptyRecycle(ctx context.Context) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *nopStorage) ListRecycle(ctx context.Context) ([]*api.RecycleEntry, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *nopStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
