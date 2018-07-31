package api

import (
	"context"
	"io"
	"mime"
	gopath "path"
)

type key int

const (
	userKey            key = 0
	tokenKey           key = 1
	publicLinkKey      key = 2
	publicLinkTokenKey key = 3
)

func ContextGetUser(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

func ContextSetUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func ContextGetAccessToken(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tokenKey).(string)
	return t, ok
}

func ContextSetAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

func ContextGetPublicLinkToken(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(publicLinkTokenKey).(string)
	return t, ok
}

func ContextSetPublicLinkToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, publicLinkTokenKey, token)
}

func ContextGetPublicLink(ctx context.Context) (*PublicLink, bool) {
	t, ok := ctx.Value(publicLinkKey).(*PublicLink)
	return t, ok
}

func ContextSetPublicLink(ctx context.Context, pl *PublicLink) context.Context {
	return context.WithValue(ctx, publicLinkKey, pl)
}

type MountOptions struct {
	ReadOnly        bool `json:"read_only"`
	SharingDisabled bool `json:"sharing_disabled"`
}

// Mount contains the information about a mount.
// Similar to "struct mntent" in /usr/include/mntent.h.
// See also getent(8).
// A Mount exposes two mount points, one path based and another namespace based.
// A path-based mount point can be '/home', a namespaced mount-point can be 'home:1234'
type Mount interface {
	Storage
	GetMountPoint() string
	GetMountPointId() string
	GetMountOptions() *MountOptions
	GetStorage() Storage
}

type MountTable struct {
	Mounts []*MountTableEntry `json:"mounts"`
}

type MountTableEntry struct {
	MountPoint      string            `json:"mount_point"`
	MountID         string            `json:"mount_id"`
	MountOptions    *MountOptions     `json:"mount_options"`
	StorageDriver   string            `json:"storage_driver"`
	StorageOptions  interface{}       `json:"storage_options"`
	StorageWrappers []*StorageWrapper `json:"storage_wrappers"`
}

type StorageWrapper struct {
	Priority int         `json:"priority"`
	Name     string      `json:"name"`
	Options  interface{} `json:"options"`
}

// A VirtualStorage is similar to the
// Linux VFS (Virtual File Switch).
type VirtualStorage interface {
	AddMount(ctx context.Context, mount Mount) error
	RemoveMount(ctx context.Context, mountPoint string) error
	ListMounts(ctx context.Context) ([]Mount, error)
	GetMount(path string) (Mount, error)
	Storage
}

type Storage interface {
	CreateDir(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
	Move(ctx context.Context, oldName, newName string) error
	GetMetadata(ctx context.Context, name string) (*Metadata, error)
	ListFolder(ctx context.Context, name string) ([]*Metadata, error)
	Upload(ctx context.Context, name string, r io.ReadCloser) error
	Download(ctx context.Context, name string) (io.ReadCloser, error)
	ListRevisions(ctx context.Context, path string) ([]*Revision, error)
	DownloadRevision(ctx context.Context, path, revisionKey string) (io.ReadCloser, error)
	RestoreRevision(ctx context.Context, path, revisionKey string) error
	ListRecycle(ctx context.Context, path string) ([]*RecycleEntry, error)
	RestoreRecycleEntry(ctx context.Context, restoreKey string) error
	EmptyRecycle(ctx context.Context, path string) error
	GetPathByID(ctx context.Context, id string) (string, error)
	SetACL(ctx context.Context, path string, readOnly bool, recipient *ShareRecipient, shareList []*FolderShare) error
	UnsetACL(ctx context.Context, path string, recipient *ShareRecipient, shareList []*FolderShare) error
	UpdateACL(ctx context.Context, path string, readOnly bool, recipient *ShareRecipient, shareList []*FolderShare) error
	GetQuota(ctx context.Context, path string) (int, int, error)
}

type PublicLinkOptions struct {
	Password         string
	ReadOnly         bool
	Expiration       uint64
	UpdatePassword   bool
	UpdateReadOnly   bool
	UpdateExpiration bool
}

type TagManager interface {
	GetTagsForKey(ctx context.Context, key string) ([]*Tag, error)
	SetTag(ctx context.Context, key, val, path string) error
	UnSetTag(ctx context.Context, key, val, path string) error
}

type PublicLinkManager interface {
	CreatePublicLink(ctx context.Context, path string, opt *PublicLinkOptions) (*PublicLink, error)
	UpdatePublicLink(ctx context.Context, id string, opt *PublicLinkOptions) (*PublicLink, error)
	InspectPublicLink(ctx context.Context, id string) (*PublicLink, error)
	InspectPublicLinkByToken(ctx context.Context, token string) (*PublicLink, error)
	ListPublicLinks(ctx context.Context) ([]*PublicLink, error)
	RevokePublicLink(ctx context.Context, token string) error

	AuthenticatePublicLink(ctx context.Context, token, password string) (*PublicLink, error)
	IsPublicLinkProtected(ctx context.Context, token string) (bool, error)
}

type ShareManager interface {
	AddFolderShare(ctx context.Context, path string, recipient *ShareRecipient, readOnly bool) (*FolderShare, error)
	GetFolderShare(ctx context.Context, shareID string) (*FolderShare, error)
	Unshare(ctx context.Context, shareID string) error
	UpdateFolderShare(ctx context.Context, shareID string, updateReadOnly, readOnly bool) (*FolderShare, error)
	ListFolderShares(ctx context.Context) ([]*FolderShare, error)

	ListReceivedShares(ctx context.Context) ([]*FolderShare, error)
	GetReceivedFolderShare(ctx context.Context, shareID string) (*FolderShare, error)
	/*
		ListFolderRecipients(ctx context.Context, path string) ([]*ShareRecipient, error)
		GetFolderSharesInPath(ctx context.Context, path string) ([]*FolderShare, error)

		MountReceivedShare(ctx context.Context, shareID string) error
		UnmountReceivedShare(ctx context.Context, shareID string) error
	*/
}

type Project struct {
	Name         string
	Path         string
	Owner        string
	AdminGroup   string
	ReadersGroup string
	WritersGroup string
}

type ProjectManager interface {
	GetAllProjects(ctx context.Context) ([]*Project, error)
	GetProject(ctx context.Context, name string) (*Project, error)
}
type UserManager interface {
	GetUserGroups(ctx context.Context, username string) ([]string, error)
	IsInGroup(ctx context.Context, username, group string) (bool, error)
}
type AuthManager interface {
	Authenticate(ctx context.Context, clientID, clientPassword string) (*User, error)
}

type TokenManager interface {
	ForgeUserToken(ctx context.Context, user *User) (string, error)
	DismantleUserToken(ctx context.Context, token string) (*User, error)

	ForgePublicLinkToken(ctx context.Context, pl *PublicLink) (string, error)
	DismantlePublicLinkToken(ctx context.Context, token string) (*PublicLink, error)
}

func GetStatus(err error) StatusCode {
	if err == nil {
		return StatusCode_OK
	}

	appError, ok := err.(AppError)
	if !ok {
		return StatusCode_UNKNOWN
	}

	switch appError.Code {
	case StorageNotFoundErrorCode:
		return StatusCode_STORAGE_NOT_FOUND
	case StorageAlreadyExistsErrorCode:
		return StatusCode_STORAGE_ALREADY_EXISTS
	case StorageNotSupportedErrorCode:
		return StatusCode_STORAGE_NOT_SUPPORTED
	case StoragePermissionDeniedErrorCode:
		return StatusCode_STORAGE_PERMISSIONDENIED
	case TokenInvalidErrorCode:
		return StatusCode_TOKEN_INVALID
	case UserNotFoundErrorCode:
		return StatusCode_USER_NOT_FOUND
	case PathInvalidError:
		return StatusCode_PATH_INVALID
	case ContextUserRequiredError:
		return StatusCode_CONTEXT_USER_REQUIRED
	case PublicLinkInvalidExpireDateErrorCode:
		return StatusCode_PUBLIC_LINK_INVALID_DATE
	case PublicLinkNotFoundErrorCode:
		return StatusCode_PUBLIC_LINK_NOT_FOUND
	default:
		return StatusCode_UNKNOWN
	}
}

func DetectMimeType(isDir bool, path string) string {
	if isDir {
		return "httpd/unix-directory"
	}
	ext := gopath.Ext(path)
	return mime.TypeByExtension(ext)
}
