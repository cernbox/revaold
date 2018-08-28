package storage_all_projects

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/cernbox/reva/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

type allProjectsStorage struct {
	vs             api.VirtualStorage
	userManager    api.UserManager
	projectManager api.ProjectManager
	logger         *zap.Logger
}

type Options struct{}

func New(opt *Options, vs api.VirtualStorage, um api.UserManager, pm api.ProjectManager, logger *zap.Logger) api.Storage {
	return &allProjectsStorage{vs, um, pm, logger}
}

func (fs *allProjectsStorage) getProject(ctx context.Context, name string) (*api.Project, string, error) {
	// path is /csc/Photos/Test
	fs.logger.Debug("get project for path", zap.String("path", name))

	items := strings.Split(name, "/")
	if len(items) < 2 {
		return nil, "", api.NewError(api.StorageNotFoundErrorCode)
	}

	projectName := items[1]
	project, err := fs.projectManager.GetProject(ctx, projectName)
	if err != nil {
		return nil, "", err
	}

	var relativePath string
	if len(items) > 2 {
		relativePath = path.Join(items[2:]...)
	}

	fs.logger.Debug("resolve project path", zap.String("path", name), zap.String("project_name", project.Name), zap.String("relativepath", relativePath), zap.String("project_path", project.Path), zap.String("project_owner", project.Owner))
	return project, relativePath, nil
}

func (fs *allProjectsStorage) GetPathByID(ctx context.Context, id string) (string, error) {
	id = "oldeosproject:" + id
	eosPath, err := fs.vs.GetPathByID(ctx, id)
	if err != nil {
		fs.logger.Error("error getting path from id", zap.Error(err))
		return "", err

	}

	right := strings.Trim(strings.TrimPrefix(eosPath, "/eos/project/"), "/") // csc or c/cbox or csc/Docs or c/cbox/Docs
	tokens := strings.Split(right, "/")

	var projectName string
	var relPath string
	if len(tokens) >= 1 {
		if len(tokens[0]) == 1 { // c/cernbox
			projectName = tokens[1]
			if len(tokens) > 2 {
				relPath = path.Join(tokens[2:]...)
			}
		} else {
			projectName = tokens[0] // csc
			if len(tokens) > 1 {
				relPath = path.Join(tokens[1:]...)
			}
		}
	}

	path := path.Join("/", projectName, relPath)
	return path, nil
}

type accessLevel int

func (al accessLevel) String() string {
	switch al {
	case 0:
		return "nothing"
	case 1:
		return "reader"
	case 2:
		return "writer"
	case 3:
		return "admin"
	default:
		return "unknown"
	}
}

const (
	accessLevelNothing accessLevel = 0
	accessLevelRead    accessLevel = 1
	accessLevelWrite   accessLevel = 2
	accessLevelAdmin   accessLevel = 3
)

func (fs *allProjectsStorage) getProjectAccess(ctx context.Context, user string, project *api.Project) accessLevel {
	groups, err := fs.userManager.GetUserGroups(ctx, user)
	if err != nil {
		fs.logger.Error("error getting groups for user", zap.String("user", user), zap.Error(err))
		return accessLevelNothing
	}

	if user == project.Owner {
		return accessLevelAdmin
	}

	level := fs.accessLevelFromGroups(ctx, groups, project)
	return level
}

func (fs *allProjectsStorage) accessLevelFromGroups(ctx context.Context, groups []string, project *api.Project) accessLevel {
	var level accessLevel = accessLevelNothing
	for _, g := range groups {
		if g == project.AdminGroup {
			return accessLevelAdmin
		}
		if g == project.WritersGroup {
			if accessLevelWrite > level {
				level = accessLevelWrite
			}
		}
		if g == project.ReadersGroup {
			if accessLevelRead > level {
				level = accessLevelRead
			}
		}
	}
	return level
}

func (fs *allProjectsStorage) getProjectMetadata(ctx context.Context, project *api.Project) (*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)

	u, err := getUserFromContext(ctx)
	if err != nil {
		fs.logger.Error("erro getting user from ctx", zap.Error(err))
		return nil, err
	}

	level := fs.getProjectAccess(ctx, u.AccountId, project)

	if level == accessLevelNothing {
		return nil, api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	prefix := path.Join("/eos/project/", project.Path)
	md, err := fs.vs.GetMetadata(newCtx, prefix)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	if level <= accessLevelRead {
		md.IsReadOnly = true
	}

	if level == accessLevelAdmin && md.IsShareable {
		md.IsShareable = true
	} else {
		md.IsShareable = false
	}

	fs.logger.Info("revad: storage_all_projects: get project metadata", zap.String("user", u.AccountId), zap.String("project", project.Name), zap.String("level", level.String()), zap.String("md",
		fmt.Sprintf("%+v", md)))
	return md, nil
}

func (fs *allProjectsStorage) SetACL(ctx context.Context, name string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}
	if !md.IsShareable {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.SetACL(newCtx, targetPath, readOnly, recipient, shareList)
}

func (fs *allProjectsStorage) UnsetACL(ctx context.Context, name string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}
	if !md.IsShareable {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.UnsetACL(newCtx, targetPath, recipient, shareList)
}

func (fs *allProjectsStorage) UpdateACL(ctx context.Context, name string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}
	if !md.IsShareable {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.UpdateACL(newCtx, targetPath, readOnly, recipient, shareList)
}

func (fs *allProjectsStorage) getProjectPath(ctx context.Context, project *api.Project, relPath string) string {
	return path.Join("/all-projects", project.Name, relPath)
}

func (fs *allProjectsStorage) GetMetadata(ctx context.Context, p string) (*api.Metadata, error) {
	if p == "/" {
		return &api.Metadata{
			Path:  "/",
			Size:  0,
			Etag:  "TODO",
			Mtime: 0,
			IsDir: true,
		}, nil
	}

	project, relPath, err := fs.getProject(ctx, p)
	if err != nil {
		return nil, err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return nil, err
	}

	targetPath := path.Join(md.Path, relPath)

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md2, err := fs.vs.GetMetadata(newCtx, targetPath)
	if err != nil {
		fs.logger.Error("error getting metadata for path", zap.String("path", targetPath), zap.Error(err))
		return nil, err
	}
	md2.Path = path.Join("/", project.Name, strings.TrimPrefix(md2.Path, md.Path))
	md2.Id = strings.Split(md2.Id, ":")[1] // md2.Id comes with eos-projects:1133 as md.Id, we only want the inode
	md2.IsReadOnly = md.IsReadOnly
	md2.IsShareable = md.IsShareable
	return md2, nil
}

func (fs *allProjectsStorage) listRoot(ctx context.Context) ([]*api.Metadata, error) {
	projects, err := fs.projectManager.GetAllProjects(ctx)
	if err != nil {
		return nil, err
	}

	// TODO(labkode): test with few
	//projects = projects[0:20]
	mds := []*api.Metadata{}
	for _, project := range projects {
		p := path.Join("/", project.Name)
		md, err := fs.GetMetadata(ctx, p)
		if err != nil {
			fs.logger.Error("revad: storage_all_projects: error getting md for project path: "+p, zap.Error(err))
			continue
		}
		// top project folder are not shareable
		md.IsShareable = false
		md.IsReadOnly = true
		mds = append(mds, md)
	}
	return mds, nil
}

// name is /<share_id>/a/b/c
func (fs *allProjectsStorage) ListFolder(ctx context.Context, name string) ([]*api.Metadata, error) {
	if name == "/" {
		return fs.listRoot(ctx)
	}

	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return nil, err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return nil, err
	}

	targetPath := path.Join(md.Path, relPath)

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	mds, err := fs.vs.ListFolder(newCtx, targetPath)
	if err != nil {
		return nil, err
	}
	for _, md2 := range mds {
		md2.Path = path.Join("/", project.Name, strings.TrimPrefix(md2.Path, md.Path))
		md2.Id = strings.Split(md2.Id, ":")[1] // md2.Id comes with eos-projects:1133 as md.Id, we only want the inode
		// apply project permissions to all children
		md2.IsReadOnly = md.IsReadOnly
		md2.IsShareable = md.IsShareable
	}

	return mds, nil
}

func (fs *allProjectsStorage) Download(ctx context.Context, name string) (io.ReadCloser, error) {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return nil, err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return nil, err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.Download(newCtx, targetPath)
}

func (fs *allProjectsStorage) Upload(ctx context.Context, name string, r io.ReadCloser) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.Upload(newCtx, targetPath, r)
}

func (fs *allProjectsStorage) Move(ctx context.Context, oldName, newName string) error {
	oldProject, oldRelPath, err := fs.getProject(ctx, oldName)
	if err != nil {
		return err
	}
	newProject, newRelPath, err := fs.getProject(ctx, newName)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, oldProject)
	if err != nil {
		fs.logger.Error("error getting metadata for old project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	if oldProject.Name != newProject.Name {
		return errors.New("cross-project rename forbidden")
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: oldProject.Owner})
	oldPath := path.Join(md.Path, oldRelPath)
	newPath := path.Join(md.Path, newRelPath)
	return fs.vs.Move(newCtx, oldPath, newPath)
}

func (fs *allProjectsStorage) GetQuota(ctx context.Context, name string) (int, int, error) {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return 0, 0, err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return 0, 0, err
	}

	if md.IsReadOnly {
		return 0, 0, api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.GetQuota(newCtx, targetPath)

}
func (fs *allProjectsStorage) CreateDir(ctx context.Context, name string) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.CreateDir(newCtx, targetPath)
}

func (fs *allProjectsStorage) Delete(ctx context.Context, name string) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	md, err := fs.getProjectMetadata(ctx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	targetPath := path.Join(md.Path, relPath)
	return fs.vs.Delete(newCtx, targetPath)
}

func (fs *allProjectsStorage) ListRevisions(ctx context.Context, path string) ([]*api.Revision, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *allProjectsStorage) DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *allProjectsStorage) RestoreRevision(ctx context.Context, path, revisionKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *allProjectsStorage) EmptyRecycle(ctx context.Context, path string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *allProjectsStorage) ListRecycle(ctx context.Context, path string) ([]*api.RecycleEntry, error) {
	return nil, api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *allProjectsStorage) RestoreRecycleEntry(ctx context.Context, restoreKey string) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}
