package public_link_manager_owncloud

import (
	"context"
	"fmt"
	gopath "path"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/reva/api"

	"database/sql"
	"github.com/bluele/gcache"
	_ "github.com/go-sql-driver/mysql"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
)

func init() {
	// Seed the random source with unix nano time
	rand.Seed(time.Now().UTC().UnixNano())
}

//TODO(labkode): add owner_id to other public link queries when consulting db
const tokenLength = 15
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const versionPrefix = ".sys.v#."

func New(dbUsername, dbPassword, dbHost string, dbPort int, dbName string, cacheSize, cacheEviction int, vfs api.VirtualStorage) (api.PublicLinkManager, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		return nil, err
	}

	cache := gcache.New(cacheSize).LFU().Build()
	return &linkManager{db: db, vfs: vfs, cache: cache, cacheEviction: time.Second * time.Duration(cacheEviction)}, nil
}

type linkManager struct {
	db            *sql.DB
	vfs           api.VirtualStorage
	cache         gcache.Cache
	cacheSize     int
	cacheEviction time.Duration
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

func (lm *linkManager) AuthenticatePublicLink(ctx context.Context, token, password string) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	dbShare, err := lm.getDBShareByToken(ctx, token)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	pb, err := lm.convertToPublicLink(ctx, dbShare)
	if err != nil {
		l.Error("error converting db share to public link", zap.Error(err))
		return nil, err
	}

	// check expiration time
	if pb.Expires != 0 {
		now := time.Now().Unix()
		if uint64(now) > pb.Expires {
			l.Warn("public link has expired", zap.String("id", pb.Id))
			return nil, api.NewError(api.PublicLinkInvalidExpireDateErrorCode)

		}
	}

	if pb.Protected {
		hashedPassword := strings.TrimPrefix(dbShare.ShareWith, "1|")
		ok := checkPasswordHash(password, hashedPassword)
		if !ok {
			return nil, api.NewError(api.PublicLinkInvalidPasswordErrorCode)
		}
	}

	return pb, nil
}

func (lm *linkManager) IsPublicLinkProtected(ctx context.Context, token string) (bool, error) {
	l := ctx_zap.Extract(ctx)
	dbShare, err := lm.getDBShareByToken(ctx, token)
	if err != nil {
		l.Error("", zap.Error(err))
		return false, err
	}
	pb, err := lm.convertToPublicLink(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return false, err
	}
	return pb.Protected, nil
}

func (lm *linkManager) InspectPublicLinkByToken(ctx context.Context, token string) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	dbShare, err := lm.getDBShareByToken(ctx, token)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	pb, err := lm.convertToPublicLink(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return pb, nil

}

func (lm *linkManager) getVersionFolderID(ctx context.Context, p string) (string, error) {
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

func (lm *linkManager) CreatePublicLink(ctx context.Context, path string, opt *api.PublicLinkOptions) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	md, err := lm.vfs.GetMetadata(ctx, path)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	var prefix, itemSource string
	if md.MigId != "" {
		prefix, itemSource = splitFileID(md.MigId)
	} else {
		prefix, itemSource = splitFileID(md.Id)
	}

	itemType := "file"
	if md.IsDir {
		itemType = "folder"
	} else {
		// if link points to a file we need to use the versions folder inode.
		if !md.IsDir {
			versionFolderID, err := lm.getVersionFolderID(ctx, md.Path)
			_, itemSource = splitFileID(versionFolderID)
			if err != nil {
				l.Error("", zap.Error(err))
				return nil, err
			}
		}

	}
	permissions := 15
	if opt.ReadOnly {
		permissions = 1
	}

	token := genToken()
	_, err = lm.getDBShareByToken(ctx, token)
	if err == nil { // token already exists, abort
		panic("the generated token already exists in the database. token: " + token)
	}

	if err != nil {
		if !api.IsErrorCode(err, api.PublicLinkNotFoundErrorCode) {
			l.Error("error checking the uniqueness of the generated token", zap.Error(err))
			return nil, err
		}
	}

	fileSource, err := strconv.ParseUint(itemSource, 10, 64)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	shareName := gopath.Base(path)

	stmtString := "insert into oc_share set share_type=?,uid_owner=?,uid_initiator=?,item_type=?,fileid_prefix=?,item_source=?,file_source=?,permissions=?,stime=?,token=?,share_name=?"
	stmtValues := []interface{}{3, u.AccountId, u.AccountId, itemType, prefix, itemSource, fileSource, permissions, time.Now().Unix(), token, shareName}

	if opt.Password != "" {
		hashedPassword, err := hashPassword(opt.Password)
		if err != nil {
			return nil, err
		}
		hashedPassword = "1|" + hashedPassword
		stmtString += ",share_with=?"
		stmtValues = append(stmtValues, hashedPassword)
	}

	if opt.Expiration != 0 {
		t := time.Unix(int64(opt.Expiration), 0)
		stmtString += ",expiration=?"
		stmtValues = append(stmtValues, t)
	}

	stmt, err := lm.db.Prepare(stmtString)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	result, err := stmt.Exec(stmtValues...)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	lastId, err := result.LastInsertId()
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	l.Info("created oc share", zap.Int64("share_id", lastId))

	pb, err := lm.InspectPublicLink(ctx, fmt.Sprintf("%d", lastId))
	if err != nil {
		l.Error("error inspecting public link", zap.Error(err))
		return nil, err
	}
	return pb, nil
}

// TODO(labkode): handle nil opt
func (lm *linkManager) UpdatePublicLink(ctx context.Context, id string, opt *api.PublicLinkOptions) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	pb, err := lm.InspectPublicLink(ctx, id)
	if err != nil {
		l.Error("error getting link before update", zap.Error(err))
		return nil, err
	}

	stmtString := "update oc_share set "
	stmtPairs := map[string]interface{}{}

	if opt.UpdatePassword {
		if opt.Password == "" {
			stmtPairs["share_with"] = ""

		} else {
			hashedPassword, err := hashPassword(opt.Password)
			if err != nil {
				return nil, err
			}
			hashedPassword = "1|" + hashedPassword
			stmtPairs["share_with"] = hashedPassword
		}
	}

	if opt.UpdateExpiration {
		t := time.Unix(int64(opt.Expiration), 0)
		stmtPairs["expiration"] = t
	}

	if opt.UpdateReadOnly {
		if opt.ReadOnly {
			stmtPairs["permissions"] = 1
		} else {
			stmtPairs["permissions"] = 15
		}
	}

	if len(stmtPairs) == 0 { // nothing to update
		return pb, nil
	}

	stmtTail := []string{}
	stmtValues := []interface{}{}

	for k, v := range stmtPairs {
		stmtTail = append(stmtTail, k+"=?")
		stmtValues = append(stmtValues, v)
	}

	stmtString += strings.Join(stmtTail, ",") + " where uid_owner=? and id=?"
	stmtValues = append(stmtValues, u.AccountId, id)

	stmt, err := lm.db.Prepare(stmtString)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	_, err = stmt.Exec(stmtValues...)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	l.Info("updated oc share")

	pb, err = lm.InspectPublicLink(ctx, id)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return pb, nil
}

func (lm *linkManager) InspectPublicLink(ctx context.Context, id string) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	dbShare, err := lm.getDBShare(ctx, u.AccountId, id)
	if err != nil {
		l.Error("cannot get db share", zap.Error(err), zap.String("id", id))
		return nil, err
	}
	pb, err := lm.convertToPublicLink(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return pb, nil
}

func (lm *linkManager) ListPublicLinks(ctx context.Context, filterByPath string) ([]*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	var fileID string
	if filterByPath != "" {
		md, err := lm.vfs.GetMetadata(ctx, filterByPath)
		if err != nil {
			return nil, err
		}

		fmt.Println("ldhugo", md)
		if !md.IsDir {
			// conver to version folder
			versionFolder := getVersionFolder(md.Path)
			mdVersion, err := lm.vfs.GetMetadata(ctx, versionFolder)
			if err == nil {
				if mdVersion.MigId != "" {
					fileID = mdVersion.MigId
				} else {
					fileID = mdVersion.Id
				}
			} else {
				// the version folder does not exist, this means that the file is not being shared by public link
				// in that case we use the inode of the files to do the search as it will never be stored in the db.
				fileID = md.Id
			}

		} else {
			if md.MigId != "" {
				fileID = md.MigId
			} else {
				fileID = md.Id
			}
		}
	}

	dbShares, err := lm.getDBShares(ctx, u.AccountId, fileID)
	if err != nil {
		return nil, err
	}

	publicLinks := []*api.PublicLink{}
	for _, dbShare := range dbShares {
		pb, err := lm.convertToPublicLink(ctx, dbShare)
		if err != nil {
			l.Error("", zap.Error(err))
			//TODO(labkode): log error and continue
			continue
		}
		publicLinks = append(publicLinks, pb)

	}
	return publicLinks, nil
}

func (lm *linkManager) RevokePublicLink(ctx context.Context, id string) error {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	stmt, err := lm.db.Prepare("delete from oc_share where uid_owner=? and id=?")
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	res, err := stmt.Exec(u.AccountId, id)
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	rowCnt, err := res.RowsAffected()
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	if rowCnt == 0 {
		err := api.NewError(api.PublicLinkNotFoundErrorCode)
		l.Error("", zap.Error(err), zap.String("id", id))
		return err
	}
	return nil
}

/*
type ocShare struct {
	ID          int64          `db:"id"`
	ShareType   int            `db:"share_type"`
	ShareWith   sql.NullString `db:"share_with"`
	UIDOwner    string         `db:"uid_owner"`
	Parent      sql.NullInt64  `db:"parent"`
	ItemType    sql.NullString `db:"item_type"`
	ItemSource  sql.NullString `db:"item_source"`
	ItemTarget  sql.NullString `db:"item_target"`
	FileSource  sql.NullInt64  `db:"file_source"`
	FileTarget  sql.NullString `db:"file_target"`
	Permissions string         `db:"permissions"`
	STime       int            `db:"stime"`
	Accepted    int            `db:"accepted"`
	Expiration  time.Time      `db:"expiration"`
	Token       sql.NullString `db:"token"`
	MailSend    int            `db:"mail_send"`
}
*/

type dbShare struct {
	ID          int
	Prefix      string
	ItemSource  string
	ShareWith   string
	Token       string
	Expiration  string
	STime       int
	ItemType    string
	Permissions int
	Owner       string
	ShareName   string
}

func (lm *linkManager) getDBShareByToken(ctx context.Context, token string) (*dbShare, error) {
	var (
		id          int
		prefix      string
		itemSource  string
		shareWith   string
		expiration  string
		stime       int
		permissions int
		itemType    string
		uidOwner    string
		shareName   string
	)

	query := "select id, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, coalesce(token,'') as token, coalesce(expiration, '') as expiration, stime, permissions, item_type, uid_owner, coalesce(share_name, '') as share_name from oc_share where share_type=? and token=?"
	if err := lm.db.QueryRow(query, 3, token).Scan(&id, &shareWith, &prefix, &itemSource, &token, &expiration, &stime, &permissions, &itemType, &uidOwner, &shareName); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.PublicLinkNotFoundErrorCode)
		}
		return nil, err
	}
	dbShare := &dbShare{ID: id, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, Token: token, Expiration: expiration, STime: stime, Permissions: permissions, ItemType: itemType, Owner: uidOwner, ShareName: shareName}
	return dbShare, nil

}

func (lm *linkManager) getDBShare(ctx context.Context, accountID, id string) (*dbShare, error) {
	l := ctx_zap.Extract(ctx)
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		l.Error("cannot parse id to int64", zap.Error(err))
		return nil, err
	}

	var (
		prefix      string
		itemSource  string
		shareWith   string
		expiration  string
		stime       int
		permissions int
		itemType    string
		token       string
		shareName   string
	)

	query := "select coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, coalesce(token,'') as token, coalesce(expiration, '') as expiration, stime, permissions, item_type, coalesce(share_name, '') as share_name from oc_share where share_type=? and uid_owner=? and id=?"
	if err := lm.db.QueryRow(query, 3, accountID, id).Scan(&shareWith, &prefix, &itemSource, &token, &expiration, &stime, &permissions, &itemType, &shareName); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.PublicLinkNotFoundErrorCode)
		}

		return nil, err
	}
	dbShare := &dbShare{ID: int(intID), Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, Token: token, Expiration: expiration, STime: stime, Permissions: permissions, ItemType: itemType, Owner: accountID, ShareName: shareName}
	return dbShare, nil

}
func (lm *linkManager) getDBShares(ctx context.Context, accountID, fileID string) ([]*dbShare, error) {
	query := "select id, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, coalesce(token,'') as token, coalesce(expiration, '') as expiration, stime, permissions, item_type, coalesce(share_name, '') as share_name from oc_share where share_type=? and uid_owner=? "
	params := []interface{}{3, accountID}

	if fileID != "" {
		prefix, itemSource := splitFileID(fileID)
		query += "and fileid_prefix=? and item_source=?"
		params = append(params, prefix, itemSource)
	}

	fmt.Println("hugo", query, params)

	rows, err := lm.db.Query(query, params...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var (
		id          int
		prefix      string
		itemSource  string
		shareWith   string
		token       string
		expiration  string
		stime       int
		permissions int
		itemType    string
		shareName   string
	)

	dbShares := []*dbShare{}
	for rows.Next() {
		err := rows.Scan(&id, &shareWith, &prefix, &itemSource, &token, &expiration, &stime, &permissions, &itemType, &shareName)
		if err != nil {
			return nil, err
		}
		dbShare := &dbShare{ID: id, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, Token: token, Expiration: expiration, STime: stime, Permissions: permissions, ItemType: itemType, Owner: accountID, ShareName: shareName}
		dbShares = append(dbShares, dbShare)

	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return dbShares, nil
}

// converToPublicLink converts  an entry from the db to a public link. It the share is to a file, we need
// to convert the version folder back to a file id, hence performing a md operation. This operation is expensive
// but we can perform aggresive caching as it a file exists the version folder will exist and viceversa.
func (lm *linkManager) convertToPublicLink(ctx context.Context, dbShare *dbShare) (*api.PublicLink, error) {
	var expires uint64
	if dbShare.Expiration != "" {
		t, err := time.Parse("2006-01-02 03:04:05", dbShare.Expiration)
		if err != nil {
			return nil, err
		}
		expires = uint64(t.Unix())
	}

	fileID := joinFileID(dbShare.Prefix, dbShare.ItemSource)
	fmt.Println("hugo db share convert", dbShare)

	var itemType api.PublicLink_ItemType
	if dbShare.ItemType == "folder" {
		itemType = api.PublicLink_FOLDER
	} else {
		itemType = api.PublicLink_FILE
		// the share points to the version folder id, we
		// need to point to the file id, so in the UI the share info
		// appears on the latest file version.
		newCtx := api.ContextSetUser(ctx, &api.User{AccountId: dbShare.Owner})
		//md, err := lm.vfs.GetMetadata(newCtx, fileID)
		md, err := lm.getCachedMetadata(newCtx, fileID)
		if err != nil {
			fmt.Println("hugo", err, fileID)
			l := ctx_zap.Extract(ctx)
			l.Error("error getting metadata for public link", zap.Error(err))
			return nil, err
		}

		versionFolder := md.Path
		filename := getFileIDFromVersionFolder(versionFolder)

		// we cannot cache the call to get metadata of the current version of the file
		// as if we cache it, we will hit the problem that after a public link share is created,
		// the file gets updated, and the cached metadata still points to the old version, with a different
		// file ID
		//md, err = lm.getCachedMetadata(newCtx, filename)
		md, err = lm.vfs.GetMetadata(newCtx, filename)
		if err != nil {
			fmt.Println("hugo", err, fileID)
			return nil, err
		}
		_, id := splitFileID(md.Id)
		fileID = joinFileID(dbShare.Prefix, id)
	}

	publicLink := &api.PublicLink{
		Id:        fmt.Sprintf("%d", dbShare.ID),
		Token:     dbShare.Token,
		Mtime:     uint64(dbShare.STime),
		Protected: dbShare.ShareWith != "",
		Path:      fileID,
		Expires:   expires,
		ReadOnly:  dbShare.Permissions == 1,
		ItemType:  itemType,
		OwnerId:   dbShare.Owner,
		Name:      dbShare.ShareName,
	}

	return publicLink, nil

}
func (lm *linkManager) getCachedMetadata(ctx context.Context, key string) (*api.Metadata, error) {
	l := ctx_zap.Extract(ctx)
	/*
		v, err := lm.cache.Get(key)
		if err == nil {
			if md, ok := v.(*api.Metadata); ok {
				l.Debug("revad: api: getCachedMetadata:  md found in cache", zap.String("path", key))
				return md, nil
			}
		}
	*/

	md, err := lm.vfs.GetMetadata(ctx, key)
	if err != nil {
		return nil, err
	}
	lm.cache.SetWithExpire(key, md, lm.cacheEviction)
	l.Debug("revad: api: getCachedMetadata: md retrieved and stored  in cache", zap.String("path", key))
	return md, nil
}

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
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

func genToken() string {
	b := make([]byte, tokenLength)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
