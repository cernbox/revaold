package public_link_manager_owncloud

import (
	"context"
	"fmt"
	"math/big"
	gopath "path"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/revaold/api"

	"crypto/rand"
	"database/sql"

	"github.com/bluele/gcache"
	_ "github.com/go-sql-driver/mysql"
	ctx_zap "github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func init() {
}

// TODO(labkode): add owner_id to other public link queries when consulting db
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
	} else if opt.DropOnly {
		permissions = 4
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

	created := time.Unix(int64(time.Now().Unix()), 0)

	tx, err := lm.db.Begin()
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec("INSERT INTO share_ids () VALUES ()")
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	lastId, err := result.LastInsertId()
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	// This is incorrect for projects... The owner should be the service account
	stmtString := "INSERT INTO public_links SET id=?,created_at=?,updated_at=?,uid_owner=?,uid_initiator=?,item_type=?,initial_path=?,inode=?,instance=?,permissions=?,orphan=?,token=?,quicklink=?,notify_uploads=?"
	stmtValues := []interface{}{lastId, created, created, u.AccountId, u.AccountId, itemType, md.EosFile, itemSource, prefix, uint8(permissions), 0, token, 0, 0}

	if opt.Password != "" {
		hashedPassword, err := hashPassword(opt.Password)
		if err != nil {
			return nil, err
		}
		hashedPassword = "1|" + hashedPassword
		stmtString += ",password=?"
		stmtValues = append(stmtValues, hashedPassword)
	}

	if opt.Expiration != 0 {
		t := time.Unix(int64(opt.Expiration), 0)
		stmtString += ",expiration=?"
		stmtValues = append(stmtValues, t)
	}
	stmt, err := tx.Prepare(stmtString)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	_, err = stmt.Exec(stmtValues...)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	l.Info("created public link", zap.Int64("share_id", lastId))

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

	stmtString := "update public_links set "
	stmtPairs := map[string]interface{}{}

	if opt.UpdatePassword {
		if opt.Password == "" {
			stmtPairs["password"] = ""

		} else {
			hashedPassword, err := hashPassword(opt.Password)
			if err != nil {
				return nil, err
			}
			hashedPassword = "1|" + hashedPassword
			stmtPairs["password"] = hashedPassword
		}
	}

	if opt.UpdateExpiration {
		t := time.Unix(int64(opt.Expiration), 0)
		stmtPairs["expiration"] = t
	}

	if opt.UpdateReadOnly || opt.UpdateDropOnly {
		if opt.ReadOnly {
			stmtPairs["permissions"] = uint8(1)
		} else if opt.DropOnly {
			stmtPairs["permissions"] = uint8(4)
		} else {
			stmtPairs["permissions"] = uint8(15)
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

	stmt, err := lm.db.Prepare("delete from public_links where uid_owner=? and id=?")
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
		instance    string
		inode       string
		expiration  string
		createdAt   string
		permissions int
		itemType    string
		uidOwner    string
		linkName    string
	)

	query := "SELECT id, coalesce(instance, '') as instance, coalesce(inode, '') as inode, coalesce(uid_owner,'') as uid_owner, coalesce(expiration, '') as expiration, created_at, permissions, item_type, coalesce(link_name, '') as link_name FROM public_links WHERE token=?"
	if err := lm.db.QueryRow(query, token).Scan(&id, &instance, &inode, &uidOwner, &expiration, &createdAt, &permissions, &itemType, &linkName); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.PublicLinkNotFoundErrorCode)
		}
		return nil, err
	}
	t, err := time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		fmt.Println("Error parsing time:", err)
		return nil, err
	}
	dbShare := &dbShare{ID: id, Prefix: instance, ItemSource: inode, ShareWith: "", Token: token, Expiration: expiration, STime: int(t.Unix()), Permissions: permissions, ItemType: itemType, Owner: uidOwner, ShareName: linkName}
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
		uidOwner    string
		instance    string
		inode       string
		expiration  string
		createdAt   string
		permissions int
		itemType    string
		token       string
		linkName    string
	)

	query := "SELECT coalesce(instance, '') as instance, coalesce(inode, '') as inode, coalesce(token,'') as token, coalesce(uid_owner, '') as uid_owner, coalesce(expiration, '') as expiration, created_at, permissions, item_type, coalesce(link_name, '') as link_name FROM public_links WHERE uid_owner=? and id=?"
	if err := lm.db.QueryRow(query, accountID, id).Scan(&instance, &inode, &token, &uidOwner, &expiration, &createdAt, &permissions, &itemType, &linkName); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.PublicLinkNotFoundErrorCode)
		}

		return nil, err
	}
	t, err := time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		fmt.Println("Error parsing time:", err)
		return nil, err
	}
	dbShare := &dbShare{ID: int(intID), Prefix: instance, ItemSource: inode, ShareWith: "", Token: token, Expiration: expiration, STime: int(t.Unix()), Permissions: permissions, ItemType: itemType, Owner: uidOwner, ShareName: linkName}
	return dbShare, nil

}
func (lm *linkManager) getDBShares(ctx context.Context, accountID, fileID string) ([]*dbShare, error) {
	query := "SELECT id, coalesce(instance, '') as instance, coalesce(inode, '') as inode, coalesce(token,'') as token, coalesce(expiration, '') as expiration, created_at, permissions, item_type, coalesce(link_name, '') as link_name FROM public_links WHERE uid_owner=? "
	params := []interface{}{accountID}

	if fileID != "" {
		prefix, itemSource := splitFileID(fileID)
		query += "and instance=? and inode=?"
		params = append(params, prefix, itemSource)
	}

	rows, err := lm.db.Query(query, params...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var (
		id          int
		instance    string
		inode       string
		expiration  string
		createdAt   string
		permissions int
		itemType    string
		token       string
		linkName    string
	)

	dbShares := []*dbShare{}
	for rows.Next() {
		err := rows.Scan(&id, &instance, &inode, &token, &expiration, &createdAt, &permissions, &itemType, &linkName)
		if err != nil {
			return nil, err
		}
		t, err := time.Parse("2006-01-02 15:04:05", createdAt)
		if err != nil {
			fmt.Println("Error parsing time:", err)
			return nil, err
		}
		dbShare := &dbShare{ID: id, Prefix: instance, ItemSource: inode, ShareWith: "", Token: token, Expiration: expiration, STime: int(t.Unix()), Permissions: permissions, ItemType: itemType, Owner: accountID, ShareName: linkName}
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
		DropOnly:  dbShare.Permissions == 4,
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
	nLetters := int64(len(letterBytes))
	for i := range b {
		nrandom, err := rand.Int(rand.Reader, big.NewInt(nLetters))
		if err != nil {
			panic(err)
		}
		b[i] = letterBytes[nrandom.Int64()]
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
