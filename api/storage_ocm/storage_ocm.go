package storage_ocm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/cernbox/revaold/api"
	"github.com/studio-b12/gowebdav"
	"go.uber.org/zap"
)

type Options struct {
	Logger *zap.Logger
}

func (opt *Options) init() {
}

func New(opt *Options) (api.Storage, error) {
	opt.init()
	s := new(localStorage)
	s.logger = opt.Logger
	return s, nil
}

type localStorage struct {
	logger *zap.Logger
}

func (fs *localStorage) convertToFileInfoWithNamespace(osFileInfo os.FileInfo, np string) *api.Metadata {
	fi := &api.Metadata{}
	fi.IsDir = osFileInfo.IsDir()
	fi.Path = path.Join("/", np)
	fi.Size = uint64(osFileInfo.Size())
	fi.Id = fi.Path
	fi.Etag = fmt.Sprintf("%d", osFileInfo.ModTime().Unix())
	fi.IsOcm = true
	fi.Mime = api.DetectMimeType(fi.IsDir, fi.Path)
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

	ocmPath := fs.getOCMPath(name)
	fs.logger.Info("CREATE DIR FROM WEBDAV SERVER", zap.String("WebdavURL", ocmPath.WebdavURL), zap.String("Token", ocmPath.Token), zap.String("OriginalFileTarget", ocmPath.OriginalFileTarget), zap.String("ConvertedlFileTarget", ocmPath.ConvertedFileTarget))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dav := gowebdav.NewClient(ocmPath.WebdavURL, ocmPath.Token, ocmPath.Token)

	return dav.Mkdir(ocmPath.ConvertedFileTarget, 0644)
}

func (fs *localStorage) Delete(ctx context.Context, name string) error {

	ocmPath := fs.getOCMPath(name)
	fs.logger.Info("DELETE FROM WEBDAV SERVER", zap.String("WebdavURL", ocmPath.WebdavURL), zap.String("Token", ocmPath.Token), zap.String("OriginalFileTarget", ocmPath.OriginalFileTarget), zap.String("ConvertedlFileTarget", ocmPath.ConvertedFileTarget))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dav := gowebdav.NewClient(ocmPath.WebdavURL, ocmPath.Token, ocmPath.Token)

	return dav.Remove(ocmPath.ConvertedFileTarget)
}

func (fs *localStorage) Move(ctx context.Context, oldName, newName string) error {

	oldPath := fs.getOCMPath(oldName)
	newPath := fs.getOCMPath(newName)
	fs.logger.Info("MOVE FROM WEBDAV SERVER", zap.String("WebdavURL", oldPath.WebdavURL), zap.String("Token", oldPath.Token), zap.String("oldConvertedFileTarget", oldPath.ConvertedFileTarget), zap.String("newConvertedFileTarget", newPath.ConvertedFileTarget))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dav := gowebdav.NewClient(oldPath.WebdavURL, oldPath.Token, oldPath.Token)

	return dav.Rename(oldPath.ConvertedFileTarget, newPath.ConvertedFileTarget, true)
}

func (fs *localStorage) GetMetadata(ctx context.Context, name string) (*api.Metadata, error) {

	ocmPath := fs.getOCMPath(name)
	fs.logger.Info("GETTING METADATA FROM WEBDAV SERVER", zap.String("name", name), zap.String("WebdavURL", ocmPath.WebdavURL), zap.String("Token", ocmPath.Token), zap.String("OriginalFileTarget", ocmPath.OriginalFileTarget), zap.String("ConvertedlFileTarget", ocmPath.ConvertedFileTarget))

	if ocmPath.ConvertedFileTarget == "/" {
		fs.logger.Info("PROVIDING FAKE INFO", zap.String("NAME", name))
		fi := &api.Metadata{}
		fi.IsDir = true
		fi.Path = path.Join("/", name)
		fi.Size = 0
		fi.Id = fi.Path
		fi.Etag = fmt.Sprintf("%d", 0)
		fi.IsOcm = true
		return fi, nil
	} else {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		dav := gowebdav.NewClient(ocmPath.WebdavURL, ocmPath.Token, ocmPath.Token)

		osFileInfo, err := dav.Stat(ocmPath.ConvertedFileTarget)
		if err != nil {
			if strings.Contains(err.Error(), "404 Not Found") {
				fs.logger.Error("NOT EXIST", zap.String("NAME", name))
				return nil, api.NewError(api.StorageNotFoundErrorCode).WithMessage(err.Error())
			}
			fs.logger.Error("CANNOT STAT", zap.String("NAME", name))
			return nil, err
		}
		return fs.convertToFileInfoWithNamespace(osFileInfo, name), nil
	}
}

func (fs *localStorage) ListFolder(ctx context.Context, name string) ([]*api.Metadata, error) {

	ocmPath := fs.getOCMPath(name)
	fs.logger.Info("LISTING FOLDER FROM WEBDAV SERVER", zap.String("WebdavURL", ocmPath.WebdavURL), zap.String("Token", ocmPath.Token), zap.String("OriginalFileTarget", ocmPath.OriginalFileTarget), zap.String("ConvertedlFileTarget", ocmPath.ConvertedFileTarget))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dav := gowebdav.NewClient(ocmPath.WebdavURL, ocmPath.Token, ocmPath.Token)

	osFileInfos, err := dav.ReadDir(ocmPath.ConvertedFileTarget)
	if err != nil {
		if os.IsNotExist(err) {
			fs.logger.Error("IS NOT EXIST", zap.String("NAME", name))
			return nil, api.NewError(api.StorageNotFoundErrorCode).WithMessage(err.Error())
		}
		fs.logger.Error("CANNOT READ DIR", zap.String("NAME", name))
		return nil, err
	}
	finfos := []*api.Metadata{}
	for _, osFileInfo := range osFileInfos {
		finfos = append(finfos, fs.convertToFileInfoWithNamespace(osFileInfo, path.Join(ocmPath.OriginalFileTarget, osFileInfo.Name())))
	}
	return finfos, nil
}

func (fs *localStorage) Upload(ctx context.Context, name string, r io.ReadCloser) error {

	ocmPath := fs.getOCMPath(name)
	fs.logger.Info("UPLOAD FROM WEBDAV SERVER", zap.String("WebdavURL", ocmPath.WebdavURL), zap.String("Token", ocmPath.Token), zap.String("OriginalFileTarget", ocmPath.OriginalFileTarget), zap.String("ConvertedlFileTarget", ocmPath.ConvertedFileTarget))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dav := gowebdav.NewClient(ocmPath.WebdavURL, ocmPath.Token, ocmPath.Token)

	return dav.WriteStream(ocmPath.ConvertedFileTarget, r, 0644)
}

func (fs *localStorage) Download(ctx context.Context, name string) (io.ReadCloser, error) {

	ocmPath := fs.getOCMPath(name)
	fs.logger.Info("DOWNLOAD FROM WEBDAV SERVER", zap.String("WebdavURL", ocmPath.WebdavURL), zap.String("Token", ocmPath.Token), zap.String("OriginalFileTarget", ocmPath.OriginalFileTarget), zap.String("ConvertedlFileTarget", ocmPath.ConvertedFileTarget))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dav := gowebdav.NewClient(ocmPath.WebdavURL, ocmPath.Token, ocmPath.Token)

	r, err := dav.ReadStream(ocmPath.ConvertedFileTarget)
	if err != nil {
		if os.IsNotExist(err) {
			fs.logger.Error("IS NOT EXIST", zap.String("NAME", name))
			return nil, api.NewError(api.StorageNotFoundErrorCode)
		}
		fs.logger.Error("ERROR DOWNLOADING", zap.String("NAME", name))
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

func (fs *localStorage) ListRecycle(ctx context.Context, path, from, to string) ([]*api.RecycleEntry, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *localStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

type ocmPath struct {
	WebdavURL           string
	Token               string
	OriginalFileTarget  string
	ConvertedFileTarget string
}

func (fs *localStorage) getOCMPath(originalPath string) *ocmPath {

	path := strings.Replace(originalPath, "/https:/", "https://", 1)
	path = strings.Replace(path, "/http:/", "http://", 1)
	values := strings.Split(path, ";")

	originalFileTarget := values[2]
	fileTarget := "/"

	fileValues := strings.FieldsFunc(originalFileTarget, getSplitFunc('/'))

	if len(fileValues) > 1 {
		fileTarget += strings.Join(fileValues[1:], "/")
	}

	return &ocmPath{
		WebdavURL:           values[0],
		Token:               values[1],
		OriginalFileTarget:  originalFileTarget,
		ConvertedFileTarget: fileTarget,
	}
}

func getSplitFunc(separator rune) func(rune) bool {
	return func(c rune) bool {
		return c == separator
	}
}
