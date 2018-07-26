package tag_manager_db

import (
	"context"
	"fmt"
	gopath "path"
	"strings"

	"github.com/cernbox/reva/api"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

const versionPrefix = ".sys.v#."

func New(dbUsername, dbPassword, dbHost string, dbPort int, dbName string, vfs api.VirtualStorage) api.TagManager {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		panic(err)
	}

	return &tagManager{db: db, vfs: vfs}
}

func (lm *tagManager) GetTagsForKey(ctx context.Context, key string) ([]*api.Tag, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("error getting user from ctx", zap.Error(err))
		return nil, err
	}

	query := "select id, item_type, fileid_prefix, fileid, coalesce(tag_val, '') as tag_val from cbox_metadata where uid=? and tag_key=?"
	rows, err := lm.db.Query(query, u.AccountId, key)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var (
		id           int64
		itemType     int
		fileIDPrefix string
		fileID       string
		tagVal       string
	)

	tags := []*api.Tag{}
	for rows.Next() {
		err := rows.Scan(&id, &itemType, &fileIDPrefix, &fileID, &tagVal)
		if err != nil {
			return nil, err
		}
		tag := &api.Tag{Id: id, ItemType: api.Tag_ItemType(itemType), Uid: u.AccountId, FileIdPrefix: fileIDPrefix, FileId: fileID, TagKey: key, TagValue: tagVal}
		tags = append(tags, tag)

	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return tags, nil
}

func getFileIDFromVersionFolder(p string) string {
	basename := gopath.Base(p)
	basename = strings.TrimPrefix(basename, "/")
	basename = strings.TrimPrefix(basename, versionPrefix)
	filename := gopath.Join(gopath.Dir(p), basename)
	return filename
}

func getVersionFolder(p string) string {
	basename := gopath.Base(p)
	versionFolder := gopath.Join(gopath.Dir(p), versionPrefix+basename)
	return versionFolder
}

type tagManager struct {
	db  *sql.DB
	vfs api.VirtualStorage
}

// getFileIDParts returns the two parts of a fileID.
// A fileID like home:1234 will be separated into the prefix (home) and the inode(1234).
func splitFileID(fileID string) (string, string) {
	tokens := strings.Split(fileID, ":")
	return tokens[0], tokens[1]
}

// joinFileID concatenates the prefix and the inode to form a valid fileID.
func joinFileID(prefix, inode string) string {
	return strings.Join([]string{prefix, inode}, ":")
}

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}
