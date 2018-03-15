package api

import (
	"context"
	"io"
)

type key int

const (
	userKey key = 0
)

func ContextGetUser(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

func ContextSetUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// MountOptions is an alias for mount options.
type MountOption int

const (
	// MountOptionReadOnly means the mount is read only.
	MountOptionReadOnly MountOption = iota

	// MounOptionReadWrit means the mount is read/write.
	MountOptionReadWrite

	// MountOptionUserContext means that operation on the mount
	// must have a user context associated.
	// This is usually the case for home filesystems and for
	// EOS impersonating the real user for accessing the data.
	MountOptionUserContext
)

// Mount contains the information about a mount.
// Similar to "struct mntent" in /usr/include/mntent.h.
// See also getent(8).
// A Mount exposes two mount points, one path based and another namespace based.
// A path-based mount point can be '/home', a namespaced mount-point can be 'home:1234'

type Mount interface {
	Storage
	GetMountPoint() string
	GetMountOptions() []MountOption
	GetMountPointId() string
}

type User struct {
	AccountID string   `json:"account_id"`
	Groups    []string `json:"groups"`
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
}

type PublicLinkOptions struct {
	Password         string
	ReadOnly         bool
	Expiration       uint64
	UpdatePassword   bool
	UpdateReadOnly   bool
	UpdateExpiration bool
}

type PublicLinkManager interface {
	CreatePublicLink(ctx context.Context, path string, opt *PublicLinkOptions) (*PublicLink, error)
	UpdatePublicLink(ctx context.Context, token string, opt *PublicLinkOptions) (*PublicLink, error)
	InspectPublicLink(ctx context.Context, token string) (*PublicLink, error)
	ListPublicLinks(ctx context.Context) ([]*PublicLink, error)
	RevokePublicLink(ctx context.Context, token string) error
}

type ShareManager interface {
	AddFolderShare(ctx context.Context, path, recipient string, readOnly bool) (*FolderShare, error)
	UpdateFolderShare(ctx context.Context, shareID string, readOnly bool) (*FolderShare, error)
	ListFolderShares(ctx context.Context) ([]*FolderShare, error)
	GetFolderShare(ctx context.Context, shareID string) (*FolderShare, error)
	Unshare(ctx context.Context, shareID string) error
	ListFolderMembers(ctx context.Context, path string) ([]string, error)
	GetFolderSharesInPath(ctx context.Context, path string) ([]*FolderShare, error)

	ListReceivedShares(ctx context.Context) ([]*FolderShare, error)
	MountReceivedShare(ctx context.Context, shareID string) error
	UnmountReceivedShare(ctx context.Context, shareID string) error
}

type AuthManager interface {
	Authenticate(ctx context.Context, clientID, clientPassword string) (*User, error)
}

type TokenManager interface {
	ForgeToken(ctx context.Context, user *User) (string, error)
	VerifyToken(ctx context, token string) bool
}
