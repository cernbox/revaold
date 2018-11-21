package storage_wrapper_home

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"
	"syscall"

	"github.com/cernbox/revaold/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
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

func (fs *homeStorage) removeNamespace(ctx context.Context, user *api.User, np string) (string, error) {
	l := ctx_zap.Extract(ctx)
	homePath := fs.getHomePath(ctx, user)
	if strings.HasPrefix(np, homePath) {
		p := strings.TrimPrefix(np, homePath)
		if p == "" {
			p = "/"
		}
		l.Debug("path conversion: internal => external", zap.String("internal", np), zap.String("external", p))
		return p, nil
	}
	err := errors.New("internal path does not start with home prefix")
	l.Error("", zap.Error(err), zap.String("internal", np), zap.String("home_prefix", homePath))
	return "", err
}

func (fs *homeStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	err = fs.wrappedStorage.SetACL(ctx, path, readOnly, recipient, shareList)
	if err != nil {
		return err
	}
	return nil
}

func (fs *homeStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	err = fs.wrappedStorage.UpdateACL(ctx, path, readOnly, recipient, shareList)
	if err != nil {
		return err
	}
	return nil
}

func (fs *homeStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return err
	}
	path = fs.getInternalPath(ctx, u, path)
	err = fs.wrappedStorage.UnsetACL(ctx, path, recipient, shareList)
	if err != nil {
		return err
	}
	return nil
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
	return fs.removeNamespace(ctx, u, path)
}

func (fs *homeStorage) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	path := fs.getInternalPath(ctx, u, p)
	md, err := fs.wrappedStorage.GetMetadata(ctx, path)
	if err != nil {
		// if p is / and err is not found we create the home directory for the user and we retry
		if api.IsErrorCode(err, api.StorageNotFoundErrorCode) && p == "/" {
			l.Warn("user does not have a homedir, we create one")
			if err2 := fs.createHome(ctx, u.AccountId); err2 != nil {
				l.Error("api: storage_wrapper_home: GetMetadata: error creating homedir for user", zap.String("user", u.AccountId), zap.Error(err))
				return nil, err
			}

			l.Info("api: storage_wrapper_home: GetMetadata: homedir create for user", zap.String("user", u.AccountId))
			// get again md for path now that we have a valid homedir

			md, err = fs.wrappedStorage.GetMetadata(ctx, path)
			if err != nil {
				l.Error("api: storage_homestorage_wrapper_homemigration: GetMetadata: error getting md just after creating homedir")
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	path, err = fs.removeNamespace(ctx, u, md.Path)
	if err != nil {
		return nil, err
	}
	md.Path = path
	return md, nil
}

// eos-create-user-directory <eos_mgm_url> <eos_user_dir_prefix> <eos_recycle_dir_prefix> <user_id>
func (fs *homeStorage) executeScript(ctx context.Context, username string) (string, string, int) {
	l := ctx_zap.Extract(ctx)

	//TODO clean all of this
	cmd := exec.Command("/bin/bash", "/root/eosuser-homedir-creation.sh", "root://eos-fake.cern.ch", "/eos/docker/user/", "/eos/docker/user/proc/recycle", username)

	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	err := cmd.Run()
	l.Info("script to create homedir executed", zap.String("cmd", fmt.Sprintf("%+v", cmd)))

	var exitStatus int
	if exiterr, ok := err.(*exec.ExitError); ok {
		// The program has exited with an exit code != 0
		// This works on both Unix and Windows. Although package
		// syscall is generally platform dependent, WaitStatus is
		// defined for both Unix and Windows and in both cases has
		// an ExitStatus() method with the same signature.
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			exitStatus = status.ExitStatus()
		}
	}

	return outBuf.String(), errBuf.String(), exitStatus
}

func (fs *homeStorage) createHome(ctx context.Context, username string) error {
	l := ctx_zap.Extract(ctx)

	_, stdErr, exitStatus := fs.executeScript(ctx, username)
	if exitStatus != 0 {
		l.Error("api: storage_homemigration: createHome: error calling script for oldhome", zap.Int("exit", exitStatus), zap.String("stderr", stdErr))
		return errors.New("error calling script to create home for oldhome")
	}
	l.Info("homedir created for user on oldhome", zap.String("user", username))
	return nil

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
		p, err := fs.removeNamespace(ctx, u, mds[i].Path)
		if err != nil {
			//omit this entry
			continue
		}
		mds[i].Path = p
	}
	return mds, nil
}

func (fs *homeStorage) GetQuota(ctx context.Context, path string) (int, int, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	path = fs.getInternalPath(ctx, u, path)
	return fs.wrappedStorage.GetQuota(ctx, path)

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

func (fs *homeStorage) ListRecycle(ctx context.Context, path, from, to string) ([]*api.RecycleEntry, error) {
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := fs.wrappedStorage.ListRecycle(ctx, path, from, to)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(entries); i++ {
		p, err := fs.removeNamespace(ctx, u, entries[i].RestorePath)
		if err != nil {
			// omit entry
			continue
		}
		entries[i].RestorePath = p
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
