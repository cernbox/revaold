package tag_manager_db

import (
	"context"
	"fmt"
	gopath "path"
	"strings"

	"github.com/cernbox/revaold/api"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

const versionPrefix = ".sys.v#."

type tagManager struct {
	db  *sql.DB
	vfs api.VirtualStorage
}

func New(dbUsername, dbPassword, dbHost string, dbPort int, dbName string, vfs api.VirtualStorage) api.TagManager {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		panic(err)
	}

	return &tagManager{db: db, vfs: vfs}
}

func (lm *tagManager) getTag(ctx context.Context, uid, prefix, fileID, key string) (*api.Tag, error) {
	var (
		id       int64
		itemType int
		tagVal   string
	)

	query := "select id,item_type,coalesce(tag_val, '') as tag_val from cbox_metadata where uid=? and fileid_prefix=? and fileid=? and tag_key=?"
	if err := lm.db.QueryRow(query, uid, prefix, fileID, key).Scan(&id, &itemType, &tagVal); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.PublicLinkNotFoundErrorCode)
		}
		return nil, err
	}

	tag := &api.Tag{FileId: fileID, FileIdPrefix: prefix, Uid: uid, TagKey: key, TagValue: tagVal, Id: id}
	return tag, nil

}

func (lm *tagManager) SetTag(ctx context.Context, key, val, path string) error {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("error getting user from ctx", zap.Error(err))
		return err
	}

	md, err := lm.vfs.GetMetadata(ctx, path)
	if err != nil {
		l.Error("error getting md for path", zap.String("path", path), zap.Error(err))
		return err
	}

	var fileID string
	if md.MigId != "" {
		fileID = md.MigId
	} else {
		fileID = md.Id
	}

	prefix, fileID := splitFileID(fileID)

	var itemType api.Tag_ItemType
	if md.IsDir {
		itemType = api.Tag_FOLDER
	} else {
		itemType = api.Tag_FILE
		// if link points to a file we need to use the versions folder inode.
		versionFolderID, err := lm.getVersionFolderID(ctx, md.Path)
		_, fileID = splitFileID(versionFolderID)
		if err != nil {
			l.Error("error getting versions folder for file", zap.Error(err))
			return err
		}
	}

	// if tag exists, we don't create a new one
	if _, err := lm.getTag(ctx, u.AccountId, prefix, fileID, key); err == nil {
		l.Info("aborting creation of new tag, as tag already exists")
		return nil
	}

	stmtString := "insert into cbox_metadata set item_type=?,uid=?,fileid_prefix=?,fileid=?,tag_key=?,tag_val=?"
	stmtValues := []interface{}{itemType, u.AccountId, prefix, fileID, key, val}

	stmt, err := lm.db.Prepare(stmtString)
	if err != nil {
		l.Error("error preparing stmt", zap.Error(err))
		return err
	}

	result, err := stmt.Exec(stmtValues...)
	if err != nil {
		l.Error("error executing stmt", zap.Error(err))
		return err
	}

	lastId, err := result.LastInsertId()
	if err != nil {
		l.Error("error getting db id", zap.Error(err))
		return err
	}

	l.Info("tag inserted", zap.Int64("id", lastId), zap.String("key", key), zap.String("val", val), zap.String("uid", u.AccountId))
	return nil
}

func (lm *tagManager) UnSetTag(ctx context.Context, key, val, path string) error {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("error getting user from ctx", zap.Error(err))
		return err
	}

	md, err := lm.vfs.GetMetadata(ctx, path)
	if err != nil {
		// return nil as the orphan background job will clean orphans
		l.Error("error getting md for path, tag is orphan", zap.String("path", path), zap.Error(err))
		return nil
	}

	var fileID string
	if md.MigId != "" {
		fileID = md.MigId
	} else {
		fileID = md.Id
	}

	prefix, fileID := splitFileID(fileID)
	if !md.IsDir {
		versionFolderID, err := lm.getVersionFolderID(ctx, md.Path)
		_, fileID = splitFileID(versionFolderID)
		if err != nil {
			l.Error("error getting versions folder for file", zap.Error(err))
			return err
		}
	}

	stmt, err := lm.db.Prepare("delete from cbox_metadata where uid=? and fileid_prefix=? and fileid=? and tag_key=?")
	if err != nil {
		l.Error("error preparing stmt for removing tag", zap.Error(err))
		return err
	}

	res, err := stmt.Exec(u.AccountId, prefix, fileID, key)
	if err != nil {
		l.Error("error executing stmt for removing tag", zap.Error(err))
		return err
	}

	_, err = res.RowsAffected()
	if err != nil {
		l.Error("error removing tag", zap.Error(err))
		return err
	}

	return nil
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

		if tag.ItemType == api.Tag_FILE {
			fileID = joinFileID(tag.FileIdPrefix, tag.FileId)
			md, err := lm.vfs.GetMetadata(ctx, fileID)
			if err != nil {
				// TOOD(labkode): log wan here
				continue
			}

			versionFolder := md.Path
			filename := getFileIDFromVersionFolder(versionFolder)

			md, err = lm.vfs.GetMetadata(ctx, filename)
			if err != nil {
				// TOOD(labkode): log wan here
				continue
			}
			_, id := splitFileID(md.Id)
			tag.FileId = id
		}

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

func (lm *tagManager) getVersionFolderID(ctx context.Context, p string) (string, error) {
	versionFolder := getVersionFolder(p)
	md, err := lm.vfs.GetMetadata(ctx, versionFolder)
	if err != nil {
		if err := lm.vfs.CreateDir(ctx, versionFolder); err != nil {
			return "", err
		}
		md, err = lm.vfs.GetMetadata(ctx, versionFolder)
		if err != nil {
			return "", err
		}
	}
	return md.Id, nil
}
