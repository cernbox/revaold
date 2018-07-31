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
	/*
		path := "/" + id
		_, _, err := fs.getProject(ctx, path)
		if err != nil {
			return "", err
		}
		return path, nil
	*/
	return "", api.NewError(api.StoragePermissionDeniedErrorCode)
}

type accessLevel int

const (
	accessLevelAdmin accessLevel = iota
	accessLevelWrite
	accessLevelRead
	accessLevelNothing
)

func (fs *allProjectsStorage) getProjectAccess(ctx context.Context, user string, project *api.Project) accessLevel {
	groups, err := fs.userManager.GetUserGroups(ctx, user)
	if err != nil {
		fs.logger.Error("error getting groups for user", zap.String("user", user), zap.Error(err))
		return accessLevelNothing
	}

	if user == project.Owner {
		fs.logger.Error("user is project admin")
		return accessLevelAdmin
	}

	return fs.accessLevelFromGroups(ctx, groups, project)
}

func (fs *allProjectsStorage) accessLevelFromGroups(ctx context.Context, groups []string, project *api.Project) accessLevel {
	for _, g := range groups {
		if g == project.AdminGroup {
			return accessLevelAdmin
		}
		if g == project.WritersGroup {
			return accessLevelWrite
		}
		if g == project.ReadersGroup {
			return accessLevelRead
		}
	}
	return accessLevelNothing
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

	if level == accessLevelRead {
		md.IsReadOnly = true
	}

	if level == accessLevelAdmin && md.IsShareable {
		md.IsShareable = true
	} else {
		md.IsShareable = false
	}

	fs.logger.Info("revad: storage_all_projects: get project metadata", zap.String("user", u.AccountId), zap.String("project", project.Name), zap.Int("level", int(level)), zap.String("md",
		fmt.Sprintf("%+v", md)))
	return md, nil
}

func (fs *allProjectsStorage) SetACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}

func (fs *allProjectsStorage) UnsetACL(ctx context.Context, path string, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
}
func (fs *allProjectsStorage) UpdateACL(ctx context.Context, path string, readOnly bool, recipient *api.ShareRecipient, shareList []*api.FolderShare) error {
	return api.NewError(api.StorageNotSupportedErrorCode)
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
	fmt.Println(project.Name + " >>> " + targetPath)

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

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md, err := fs.getProjectMetadata(newCtx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return nil, err
	}

	targetPath := path.Join(md.Path, relPath)
	fmt.Println(project.Name + " >>> " + targetPath)

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

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md, err := fs.getProjectMetadata(newCtx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return nil, err
	}

	targetPath := path.Join(md.Path, relPath)
	fmt.Println(project.Name + " >>> " + targetPath)
	return fs.vs.Download(newCtx, targetPath)
}

func (fs *allProjectsStorage) Upload(ctx context.Context, name string, r io.ReadCloser) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md, err := fs.getProjectMetadata(newCtx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	targetPath := path.Join(md.Path, relPath)
	fmt.Println(project.Name + " >>> " + targetPath)
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

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: oldProject.Owner})
	md, err := fs.getProjectMetadata(newCtx, oldProject)
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

	oldPath := path.Join(md.Path, oldRelPath)
	newPath := path.Join(md.Path, newRelPath)
	fmt.Printf("revad: storage_all_projects: move from(%s) to (%s)\n", oldPath, newPath)
	return fs.vs.Move(newCtx, oldPath, newPath)
}

func (fs *allProjectsStorage) GetQuota(ctx context.Context, name string) (int, int, error) {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return 0, 0, err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md, err := fs.getProjectMetadata(newCtx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return 0, 0, err
	}

	if md.IsReadOnly {
		return 0, 0, api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	targetPath := path.Join(md.Path, relPath)
	fmt.Println(project.Name + " >>> " + targetPath)
	return fs.vs.GetQuota(newCtx, targetPath)

}
func (fs *allProjectsStorage) CreateDir(ctx context.Context, name string) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md, err := fs.getProjectMetadata(newCtx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	targetPath := path.Join(md.Path, relPath)
	fmt.Println(project.Name + " >>> " + targetPath)

	return fs.vs.CreateDir(newCtx, targetPath)
}

func (fs *allProjectsStorage) Delete(ctx context.Context, name string) error {
	project, relPath, err := fs.getProject(ctx, name)
	if err != nil {
		return err
	}

	newCtx := api.ContextSetUser(ctx, &api.User{AccountId: project.Owner})
	md, err := fs.getProjectMetadata(newCtx, project)
	if err != nil {
		fs.logger.Error("error getting metadata for project", zap.Error(err))
		return err
	}

	if md.IsReadOnly {
		return api.NewError(api.StoragePermissionDeniedErrorCode)
	}

	targetPath := path.Join(md.Path, relPath)
	fmt.Println(project.Name + " >>> " + targetPath)
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
