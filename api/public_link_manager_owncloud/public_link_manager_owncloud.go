package public_link_manager_owncloud

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/reva/api"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
)

const tokenLength = 15
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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

func New(dbUsername, dbPassword, dbHost string, dbPort int, dbName string, vfs api.VirtualStorage) (api.PublicLinkManager, error) {
	fmt.Println(dbUsername)
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		return nil, err
	}

	return &linkManager{db: db, vfs: vfs}, nil
}

type linkManager struct {
	db  *sql.DB
	vfs api.VirtualStorage
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

	itemType := "file"
	if md.IsDir {
		itemType = "folder"
	}
	permissions := 15
	if opt.ReadOnly {
		permissions = 1
	}
	token := genToken()

	itemSource := strings.Split(md.Id, ":")[1]
	fileSource, err := strconv.ParseUint(itemSource, 10, 64)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	stmtString := "insert into oc_share set share_type=?,uid_owner=?,uid_initiator=?,item_type=?,item_source=?,file_source=?,permissions=?,stime=?,token=?"
	stmtValues := []interface{}{3, u.AccountId, u.AccountId, itemType, itemSource, fileSource, permissions, time.Now().Unix(), token}

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
		l.Error("", zap.Error(err))
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
	// TODO(labkode): check that this works after the migration.
	pb.Path = "home:" + pb.Path // hardcoded mount
	return pb, nil
}

func (lm *linkManager) ListPublicLinks(ctx context.Context) ([]*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	dbShares, err := lm.getDBShares(ctx, u.AccountId)
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
		pb.Path = "home:" + pb.Path // hardcoded mount
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
	ItemSource  string
	ShareWith   string
	Token       string
	Expiration  string
	STime       int
	ItemType    string
	Permissions int
}

func (lm *linkManager) getDBShare(ctx context.Context, accountID, id string) (*dbShare, error) {
	l := ctx_zap.Extract(ctx)
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		l.Error("cannot parse id to int64", zap.Error(err))
		return nil, err
	}

	var (
		itemSource  string
		shareWith   string
		expiration  string
		stime       int
		permissions int
		itemType    string
		token       string
	)

	query := "select coalesce(share_with, '') as share_with, coalesce(item_source, '') as item_source, coalesce(token,'') as token, coalesce(expiration, '') as expiration, stime, permissions, item_type from oc_share where share_type=? and uid_owner=? and id=?"
	if err := lm.db.QueryRow(query, 3, accountID, id).Scan(&shareWith, &itemSource, &token, &expiration, &stime, &permissions, &itemType); err != nil {
		// TODO(labkode): return not found error code
		return nil, err
	}
	dbShare := &dbShare{ID: int(intID), ItemSource: itemSource, ShareWith: shareWith, Token: token, Expiration: expiration, STime: stime, Permissions: permissions, ItemType: itemType}
	return dbShare, nil

}
func (lm *linkManager) getDBShares(ctx context.Context, accountID string) ([]*dbShare, error) {
	query := "select id, coalesce(share_with, '') as share_with, coalesce(item_source, '') as item_source, coalesce(token,'') as token, coalesce(expiration, '') as expiration, stime, permissions, item_type from oc_share where share_type=? and uid_owner=?"
	rows, err := lm.db.Query(query, 3, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		id          int
		itemSource  string
		shareWith   string
		token       string
		expiration  string
		stime       int
		permissions int
		itemType    string
	)

	dbShares := []*dbShare{}
	for rows.Next() {
		err := rows.Scan(&id, &shareWith, &itemSource, &token, &expiration, &stime, &permissions, &itemType)
		if err != nil {
			return nil, err
		}
		dbShare := &dbShare{ID: id, ItemSource: itemSource, ShareWith: shareWith, Token: token, Expiration: expiration, STime: stime, Permissions: permissions, ItemType: itemType}
		dbShares = append(dbShares, dbShare)

	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return dbShares, nil
}

func (lm *linkManager) convertToPublicLink(ctx context.Context, dbShare *dbShare) (*api.PublicLink, error) {
	var expires uint64
	if dbShare.Expiration != "" {
		t, err := time.Parse("2006-01-02 03:04:05", dbShare.Expiration)
		if err != nil {
			return nil, err
		}
		expires = uint64(t.Unix())
	}

	var itemType api.PublicLink_ItemType
	if dbShare.ItemType == "folder" {
		itemType = api.PublicLink_FOLDER
	} else {

		itemType = api.PublicLink_FILE
	}
	publicLink := &api.PublicLink{
		Id:        fmt.Sprintf("%d", dbShare.ID),
		Token:     dbShare.Token,
		Mtime:     uint64(dbShare.STime),
		Protected: dbShare.ShareWith != "",
		Path:      dbShare.ItemSource,
		Expires:   expires,
		ReadOnly:  dbShare.Permissions == 1,
		ItemType:  itemType,
	}
	return publicLink, nil

}

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}
