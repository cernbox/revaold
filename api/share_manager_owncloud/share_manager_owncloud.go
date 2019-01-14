package share_manager_owncloud

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/revaold/api"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func New(dbUsername, dbPassword, dbHost string, dbPort int, dbName string, vfs api.VirtualStorage, um api.UserManager) (api.ShareManager, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		return nil, err
	}

	return &shareManager{db: db, vfs: vfs, um: um}, nil
}

type shareManager struct {
	db  *sql.DB
	vfs api.VirtualStorage
	um  api.UserManager
}

func (sm *shareManager) UnmountReceivedShare(ctx context.Context, id string) error {
	u, err := getUserFromContext(ctx)
	if err != nil {
		err = errors.Wrap(err, "error getting user context")
		return err
	}

	err = sm.rejectShare(ctx, u.AccountId, id)
	if err != nil {
		err = errors.Wrapf(err, "error rejecting db share: id=%s user=%s", id, u.AccountId)
		return err
	}

	return nil
}

func (sm *shareManager) rejectShare(ctx context.Context, receiver, id string) error {
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		err = errors.Wrapf(err, "cannot parse id to int64: id=%s", id)
		return err
	}

	_, err = sm.getDBShareWithMe(ctx, receiver, id)
	if err != nil {
		err = errors.Wrapf(err, "error getting share: id=%s user=%s", id, receiver)
		return err
	}

	query := "insert into oc_share_acl(id, rejected_by) values(?, ?)"
	stmt, err := sm.db.Prepare(query)
	if err != nil {
		err = errors.Wrapf(err, "error preparing statement: id=%s", id)
		return err
	}

	_, err = stmt.Exec(intID, receiver)
	if err != nil {
		err = errors.Wrapf(err, "error updating db: id=%s", id)
		return err
	}
	return nil
}

func (sm *shareManager) GetReceivedFolderShare(ctx context.Context, id string) (*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	dbShare, err := sm.getDBShareWithMe(ctx, u.AccountId, id)
	if err != nil {
		l.Error("cannot get db share", zap.Error(err), zap.String("id", id), zap.String("user", u.AccountId))
		return nil, err
	}

	share, err := sm.convertToReceivedFolderShare(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return share, nil
}
func (sm *shareManager) ListReceivedShares(ctx context.Context) ([]*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	dbShares, err := sm.getDBSharesWithMe(ctx, u.AccountId)
	if err != nil {
		return nil, err
	}
	shares := []*api.FolderShare{}
	for _, dbShare := range dbShares {
		share, err := sm.convertToReceivedFolderShare(ctx, dbShare)
		if err != nil {
			l.Error("", zap.Error(err))
			//TODO(labkode): log error and continue
			continue
		}
		shares = append(shares, share)

	}
	return shares, nil

}

func (sm *shareManager) ListFolderShares(ctx context.Context, filterByPath string) ([]*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	var shareID string
	if filterByPath != "" {
		md, err := sm.vfs.GetMetadata(ctx, filterByPath)
		if err != nil {
			return nil, err
		}

		if md.MigId != "" {
			shareID = md.MigId
		} else {
			shareID = md.Id
		}
	}

	dbShares, err := sm.getDBShares(ctx, u.AccountId, shareID)
	if err != nil {
		return nil, err
	}
	shares := []*api.FolderShare{}
	for _, dbShare := range dbShares {
		share, err := sm.convertToFolderShare(ctx, dbShare)
		if err != nil {
			l.Error("", zap.Error(err))
			//TODO(labkode): log error and continue
			continue
		}
		shares = append(shares, share)

	}
	return shares, nil
}

func (sm *shareManager) UpdateFolderShare(ctx context.Context, id string, updateReadOnly, readOnly bool) (*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	share, err := sm.GetFolderShare(ctx, id)
	if err != nil {
		l.Error("error getting share before update", zap.Error(err))
		return nil, err
	}

	md, err := sm.vfs.GetMetadata(ctx, share.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	stmtString := "update oc_share set "
	stmtPairs := map[string]interface{}{}

	if updateReadOnly {
		if readOnly {
			stmtPairs["permissions"] = 1
		} else {
			stmtPairs["permissions"] = 15
		}
	}

	if len(stmtPairs) == 0 { // nothing to update
		return share, nil
	}

	stmtTail := []string{}
	stmtValues := []interface{}{}

	for k, v := range stmtPairs {
		stmtTail = append(stmtTail, k+"=?")
		stmtValues = append(stmtValues, v)
	}

	stmtString += strings.Join(stmtTail, ",") + " where uid_owner=? and id=?"
	stmtValues = append(stmtValues, u.AccountId, id)

	stmt, err := sm.db.Prepare(stmtString)
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

	share, err = sm.GetFolderShare(ctx, id)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	//  update acl on the storage
	err = sm.vfs.SetACL(ctx, md.Path, share.ReadOnly, share.Recipient, []*api.FolderShare{})
	if err != nil {
		l.Error("error setting acl on storage, rollbacking operation", zap.Error(err))
		err2 := sm.Unshare(ctx, share.Id)
		if err2 != nil {
			l.Error("cannot remove non commited share, fix manually", zap.Error(err2), zap.String("share_id", share.Id))
			return nil, err2
		}
		return nil, err
	}

	l.Info("share commited on storage acl", zap.String("share_id", share.Id))
	return share, nil
}
func (sm *shareManager) Unshare(ctx context.Context, id string) error {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	share, err := sm.GetFolderShare(ctx, id)
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	stmt, err := sm.db.Prepare("delete from oc_share where uid_owner=? and id=?")
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

	// re-set acl on the storage
	err = sm.vfs.UnsetACL(ctx, share.Path, share.Recipient, []*api.FolderShare{})
	if err != nil {
		l.Error("error removing acl on storage, fix manually", zap.Error(err))
		return err
	}

	l.Info("share removed from storage acl", zap.String("share_id", share.Id))

	return nil
}

func (sm *shareManager) GetFolderShare(ctx context.Context, id string) (*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	dbShare, err := sm.getDBShare(ctx, u.AccountId, id)
	if err != nil {
		l.Error("cannot get db share", zap.Error(err), zap.String("id", id))
		return nil, err
	}

	share, err := sm.convertToFolderShare(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return share, nil
}

func (sm *shareManager) AddFolderShare(ctx context.Context, p string, recipient *api.ShareRecipient, readOnly bool) (*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	md, err := sm.vfs.GetMetadata(ctx, p)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	// TODO(labkode): use another error cde
	if !md.IsDir {
		return nil, api.NewError(api.StorageNotSupportedErrorCode)
	}

	itemType := "folder"

	permissions := 15
	if readOnly {
		permissions = 1
	}

	var prefix string
	var itemSource string
	if md.MigId != "" {
		prefix, itemSource = splitFileID(md.MigId)
	} else {
		prefix, itemSource = splitFileID(md.Id)
	}

	fileSource, err := strconv.ParseUint(itemSource, 10, 64)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	shareType := 0 // user
	if recipient.Type == api.ShareRecipient_GROUP {
		shareType = 1
	}

	targetPath := path.Join("/", path.Base(p))

	stmtString := "insert into oc_share set share_type=?,uid_owner=?,uid_initiator=?,item_type=?,fileid_prefix=?,item_source=?,file_source=?,permissions=?,stime=?,share_with=?,file_target=?"
	stmtValues := []interface{}{shareType, u.AccountId, u.AccountId, itemType, prefix, itemSource, fileSource, permissions, time.Now().Unix(), recipient.Identity, targetPath}

	stmt, err := sm.db.Prepare(stmtString)
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

	share, err := sm.GetFolderShare(ctx, fmt.Sprintf("%d", lastId))
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	// set acl on the storage
	err = sm.vfs.SetACL(ctx, p, readOnly, recipient, []*api.FolderShare{})
	if err != nil {
		l.Error("error setting acl on storage, rollbacking operation", zap.Error(err))
		err2 := sm.Unshare(ctx, share.Id)
		if err2 != nil {
			l.Error("cannot remove non commited share, fix manually", zap.Error(err2), zap.String("share_id", share.Id))
			return nil, err2
		}
		return nil, err
	}

	l.Info("share commited on storage acl", zap.String("share_id", share.Id))

	return share, nil
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
	UIDOwner    string
	Prefix      string
	ItemSource  string
	ShareWith   string
	Permissions int
	ShareType   int
	STime       int
	FileTarget  string
	State       int
}

func (sm *shareManager) getDBShareWithMe(ctx context.Context, accountID, id string) (*dbShare, error) {
	l := ctx_zap.Extract(ctx)
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		l.Error("cannot parse id to int64", zap.Error(err))
		return nil, err
	}

	var (
		uidOwner    string
		shareWith   string
		prefix      string
		itemSource  string
		shareType   int
		stime       int
		permissions int
		fileTarget  string
		state       int
	)

	groups, err := sm.um.GetUserGroups(ctx, accountID)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	queryArgs := []interface{}{id, accountID}
	groupArgs := []interface{}{}
	for _, v := range groups {
		groupArgs = append(groupArgs, v)
	}

	var query string

	if len(groups) > 1 {
		query = "select coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target, accepted from oc_share where id=? and (accepted=0 or accepted=1) and (share_with=? or share_with in (?" + strings.Repeat(",?", len(groups)-1) + ")) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
		queryArgs = append(queryArgs, groupArgs...)
		queryArgs = append(queryArgs, accountID)
	} else {
		query = "select coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target, accepted from oc_share where id=? and (accepted=0 or accepted=1) and (share_with=?) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
		queryArgs = append(queryArgs, accountID)
	}

	if err := sm.db.QueryRow(query, queryArgs...).Scan(&uidOwner, &shareWith, &prefix, &itemSource, &stime, &permissions, &shareType, &fileTarget, &state); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.FolderShareNotFoundErrorCode)
		}
		return nil, err
	}
	dbShare := &dbShare{ID: int(intID), UIDOwner: uidOwner, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, STime: stime, Permissions: permissions, ShareType: shareType, FileTarget: fileTarget, State: state}
	return dbShare, nil

}

func (sm *shareManager) getDBSharesWithMe(ctx context.Context, accountID string) ([]*dbShare, error) {
	l := ctx_zap.Extract(ctx)
	groups, err := sm.um.GetUserGroups(ctx, accountID)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	queryArgs := []interface{}{0, 1, accountID, accountID}
	groupArgs := []interface{}{}
	for _, v := range groups {
		groupArgs = append(groupArgs, v)
	}

	var query string

	if len(groups) > 1 {
		query = "select id, coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target from oc_share where (accepted=0 or accepted=1) and (share_type=? or share_type=?) and uid_owner!=? and (share_with=? or share_with in (?" + strings.Repeat(",?", len(groups)-1) + ")) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
		queryArgs = append(queryArgs, groupArgs...)
		queryArgs = append(queryArgs, accountID)
	} else {
		query = "select id, coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target from oc_share where (accepted=0 or accepted=1) and (share_type=? or share_type=?) and uid_owner!=? and (share_with=?) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
		queryArgs = append(queryArgs, accountID)
	}
	rows, err := sm.db.Query(query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		id          int
		uidOwner    string
		shareWith   string
		prefix      string
		itemSource  string
		shareType   int
		stime       int
		permissions int
		fileTarget  string
	)

	dbShares := []*dbShare{}
	for rows.Next() {
		err := rows.Scan(&id, &uidOwner, &shareWith, &prefix, &itemSource, &stime, &permissions, &shareType, &fileTarget)
		if err != nil {
			return nil, err
		}
		dbShare := &dbShare{ID: id, UIDOwner: uidOwner, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, STime: stime, Permissions: permissions, ShareType: shareType, FileTarget: fileTarget}
		dbShares = append(dbShares, dbShare)

	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return dbShares, nil
}

func (sm *shareManager) getDBShare(ctx context.Context, accountID, id string) (*dbShare, error) {
	l := ctx_zap.Extract(ctx)
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		l.Error("cannot parse id to int64", zap.Error(err))
		return nil, err
	}

	var (
		uidOwner    string
		shareWith   string
		prefix      string
		itemSource  string
		shareType   int
		stime       int
		permissions int
	)

	query := "select coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type from oc_share where uid_owner=? and id=?"
	if err := sm.db.QueryRow(query, accountID, id).Scan(&uidOwner, &shareWith, &prefix, &itemSource, &stime, &permissions, &shareType); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.FolderShareNotFoundErrorCode)
		}
		return nil, err
	}
	dbShare := &dbShare{ID: int(intID), UIDOwner: uidOwner, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, STime: stime, Permissions: permissions, ShareType: shareType}
	return dbShare, nil

}

func (sm *shareManager) getDBShares(ctx context.Context, accountID, filterByFileID string) ([]*dbShare, error) {
	query := "select id, coalesce(uid_owner, '') as uid_owner,  coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type from oc_share where uid_owner=? and (share_type=? or share_type=?) "
	params := []interface{}{accountID, 0, 1}
	if filterByFileID != "" {
		prefix, itemSource := splitFileID(filterByFileID)
		query += "and fileid_prefix=? and item_source=?"
		params = append(params, prefix, itemSource)
	}

	rows, err := sm.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		id          int
		uidOwner    string
		shareWith   string
		prefix      string
		itemSource  string
		shareType   int
		stime       int
		permissions int
	)

	dbShares := []*dbShare{}
	for rows.Next() {
		err := rows.Scan(&id, &uidOwner, &shareWith, &prefix, &itemSource, &stime, &permissions, &shareType)
		if err != nil {
			return nil, err
		}
		dbShare := &dbShare{ID: id, UIDOwner: uidOwner, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, STime: stime, Permissions: permissions, ShareType: shareType}
		dbShares = append(dbShares, dbShare)

	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return dbShares, nil
}

func (sm *shareManager) convertToReceivedFolderShare(ctx context.Context, dbShare *dbShare) (*api.FolderShare, error) {
	var recipientType api.ShareRecipient_RecipientType
	if dbShare.ShareType == 0 {
		recipientType = api.ShareRecipient_USER
	} else {
		recipientType = api.ShareRecipient_GROUP
	}
	path := joinFileID(dbShare.Prefix, dbShare.ItemSource)
	share := &api.FolderShare{
		OwnerId:  dbShare.UIDOwner,
		Id:       fmt.Sprintf("%d", dbShare.ID),
		Mtime:    uint64(dbShare.STime),
		Path:     path,
		ReadOnly: dbShare.Permissions == 1,
		Recipient: &api.ShareRecipient{
			Identity: dbShare.ShareWith,
			Type:     recipientType,
		},
		Target: dbShare.FileTarget,
	}
	return share, nil

}

func (sm *shareManager) convertToFolderShare(ctx context.Context, dbShare *dbShare) (*api.FolderShare, error) {
	var recipientType api.ShareRecipient_RecipientType
	if dbShare.ShareType == 0 {
		recipientType = api.ShareRecipient_USER
	} else {
		recipientType = api.ShareRecipient_GROUP
	}

	path := joinFileID(dbShare.Prefix, dbShare.ItemSource)
	share := &api.FolderShare{
		OwnerId:  dbShare.UIDOwner,
		Id:       fmt.Sprintf("%d", dbShare.ID),
		Mtime:    uint64(dbShare.STime),
		Path:     path,
		ReadOnly: dbShare.Permissions == 1,
		Recipient: &api.ShareRecipient{
			Identity: dbShare.ShareWith,
			Type:     recipientType,
		},
	}
	return share, nil

}

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
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
