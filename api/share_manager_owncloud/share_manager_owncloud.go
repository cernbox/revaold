package share_manager_owncloud

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/revaold/api"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
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

func (sm *shareManager) GetReceivedOCMShare(ctx context.Context, id string) (*api.FolderShare, error) {
	// talk to OCM database
	// copy paste from GetReceivedFolderShare
	// create convertToReceivedOCMShare

	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	dbShare, err := sm.getDBOCMShareWithMe(ctx, u.AccountId, id)
	if err != nil {
		l.Error("cannot get db share", zap.Error(err), zap.String("id", id), zap.String("user", u.AccountId))
		return nil, err
	}

	provider, err := sm.getDBOCMProvider(ctx, dbShare.OCMDomain)
	if err != nil {
		l.Error("cannot get db provider", zap.Error(err), zap.String("host", dbShare.OCMDomain))
		return nil, err
	}

	share, err := sm.convertToReceivedOCMShare(ctx, dbShare, provider.WebdavEndpoint)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return share, nil

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

func (sm *shareManager) ListOCMShares(ctx context.Context) ([]*api.OCMShare, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	dbShares, err := sm.getDBShares(ctx, u.AccountId, "")
	if err != nil {
		return nil, err
	}
	shares := []*api.OCMShare{}
	for _, dbShare := range dbShares {
		share, err := sm.convertToOCMShare(ctx, dbShare)
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
	dbShare, err := sm.GetShare(ctx, id)

	if err != nil {
		return nil, err
	}

	share, err := sm.convertToFolderShare(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return share, nil
}

func (sm *shareManager) GetOCMShare(ctx context.Context, id string) (*api.OCMShare, error) {
	l := ctx_zap.Extract(ctx)
	dbShare, err := sm.GetShare(ctx, id)

	if err != nil {
		return nil, err
	}

	share, err := sm.convertToOCMShare(ctx, dbShare)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return share, nil
}

func (sm *shareManager) GetShare(ctx context.Context, id string) (*dbShare, error) {
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

	return dbShare, nil
}

func (sm *shareManager) AddFolderShare(ctx context.Context, p string, recipient *api.ShareRecipient, readOnly bool) (*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	shareType := 0 // user
	if recipient.Type == api.ShareRecipient_GROUP {
		shareType = 1
	}
	lastId, err := sm.AddShare(ctx, shareType, p, recipient.Identity, readOnly, "")

	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

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

func (sm *shareManager) AddOCMShare(ctx context.Context, p string, recipient string) (*api.OCMShare, error) {
	l := ctx_zap.Extract(ctx)

	lastId, err := sm.AddShare(ctx, 4, p, recipient, true, uuid.New().String())

	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	share, err := sm.GetOCMShare(ctx, fmt.Sprintf("%d", lastId))
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	l.Info("share commited on storage acl", zap.String("share_id", share.Id))

	// Propagate the share to the receiving provider
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	form := url.Values{}
	form.Add("shareID", share.Id)
	req, err := http.NewRequest("POST", "http://localhost:9994/internal/shares", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		l.Error("error preparing request to ocmd", zap.Error(err))
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		l.Error("error doing request to ocmd", zap.Error(err))
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		// TODO get error message
		sm.Unshare(ctx, share.Id)
		return nil, errors.New("Error while sending to remote provider")
	}

	return share, nil
}

func (sm *shareManager) AddShare(ctx context.Context, shareType int, p string, recipient string, readOnly bool, token string) (int64, error) {
	l := ctx_zap.Extract(ctx)
	u, err := getUserFromContext(ctx)
	if err != nil {
		l.Error("", zap.Error(err))
		return 0, err
	}
	md, err := sm.vfs.GetMetadata(ctx, p)
	if err != nil {
		l.Error("", zap.Error(err))
		return 0, err
	}

	// TODO(labkode): use another error cde
	if !md.IsDir {
		return 0, api.NewError(api.StorageNotSupportedErrorCode)
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
		return 0, err
	}

	targetPath := path.Join("/", path.Base(p))

	stmtString := "insert into oc_share set share_type=?,uid_owner=?,uid_initiator=?,item_type=?,fileid_prefix=?,item_source=?,file_source=?,permissions=?,stime=?,share_with=?,file_target=?,token=?"
	stmtValues := []interface{}{shareType, u.AccountId, u.AccountId, itemType, prefix, itemSource, fileSource, permissions, time.Now().Unix(), recipient, targetPath, token}

	if shareType == 4 {
		//THIS IS AN OCM SHARE
		stmtString += ",ocm_eos_base_path=?"
		stmtValues = append(stmtValues, md.EosFile)
	}

	stmt, err := sm.db.Prepare(stmtString)
	if err != nil {
		l.Error("", zap.Error(err))
		return 0, err
	}

	result, err := stmt.Exec(stmtValues...)
	if err != nil {
		l.Error("", zap.Error(err))
		return 0, err
	}
	lastId, err := result.LastInsertId()

	l.Info("created oc share", zap.Int64("share_id", lastId))
	return lastId, err
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

type ocmProvider struct {
	Domain         string
	APIVersion     string
	APIEndpoint    string
	WebdavEndpoint string
}

func (sm *shareManager) getDBOCMProvider(ctx context.Context, domain string) (*ocmProvider, error) {
	l := ctx_zap.Extract(ctx)

	var (
		apiVersion     string
		apiEndpoint    string
		webdavEndpoint string
	)
	query := fmt.Sprintf("SELECT api_version, api_endpoint, webdav_endpoint FROM ocm_providers WHERE domain=?")
	err := sm.db.QueryRow(query, domain).Scan(&apiVersion, &apiEndpoint, &webdavEndpoint)
	if err != nil {
		if err == sql.ErrNoRows {
			l.Error("Cannot find provider", zap.String("domain", domain))
		} else {
			l.Error("CANNOT QUERY STATEMENT")
		}
		return nil, err
	}

	provider := &ocmProvider{
		Domain:         domain,
		APIVersion:     apiVersion,
		APIEndpoint:    apiEndpoint,
		WebdavEndpoint: webdavEndpoint,
	}
	return provider, nil

}
func (sm *shareManager) getDBOCMProviders(ctx context.Context) ([]*ocmProvider, error) {

	rows, err := sm.db.Query("SELECT domain, api_version, api_endpoint, webdav_endpoint FROM ocm_providers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		domain         string
		apiVersion     string
		apiEndpoint    string
		webdavEndpoint string
	)

	dbProviders := []*ocmProvider{}
	for rows.Next() {
		err := rows.Scan(&domain, &apiVersion, &apiEndpoint, &webdavEndpoint)
		if err != nil {
			return nil, err
		}
		dbProvider := &ocmProvider{
			Domain:         domain,
			APIVersion:     apiVersion,
			APIEndpoint:    apiEndpoint,
			WebdavEndpoint: webdavEndpoint,
		}
		dbProviders = append(dbProviders, dbProvider)

	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return dbProviders, nil

}

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
	Token       string
	OCMDomain   string
}

func (sm *shareManager) getDBOCMShareWithMe(ctx context.Context, accountID, id string) (*dbShare, error) {
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
		token       string
		ocmDomain   string
	)

	queryArgs := []interface{}{id, accountID}

	var query string

	query = "select coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target, accepted, coalesce(token, ''), ocm_domain from oc_share where id=? and (accepted=0 or accepted=1) and (share_with=?) and share_type=5 and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
	queryArgs = append(queryArgs, accountID)

	if err := sm.db.QueryRow(query, queryArgs...).Scan(&uidOwner, &shareWith, &prefix, &itemSource, &stime, &permissions, &shareType, &fileTarget, &state, &token, &ocmDomain); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.FolderShareNotFoundErrorCode)
		}
		return nil, err
	}
	dbShare := &dbShare{ID: int(intID), UIDOwner: uidOwner, Prefix: prefix, ItemSource: itemSource, ShareWith: shareWith, STime: stime, Permissions: permissions, ShareType: shareType, FileTarget: fileTarget, State: state, Token: token, OCMDomain: ocmDomain}
	return dbShare, nil

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
		query = "select coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target, accepted from oc_share where id=? and (accepted=0 or accepted=1) and share_type<> 5 and (share_with=? or share_with in (?" + strings.Repeat(",?", len(groups)-1) + ")) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
		queryArgs = append(queryArgs, groupArgs...)
		queryArgs = append(queryArgs, accountID)
	} else {
		query = "select coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target, accepted from oc_share where id=? and (accepted=0 or accepted=1) and (share_with=?) and share_type<> 5 and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
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
	queryArgs := []interface{}{0, 1, 5, accountID, accountID}
	groupArgs := []interface{}{}
	for _, v := range groups {
		groupArgs = append(groupArgs, v)
	}

	var query string

	if len(groups) > 1 {
		query = "select id, coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target from oc_share where (accepted=0 or accepted=1) and (share_type=? or share_type=? or share_type=?) and uid_owner!=? and (share_with=? or share_with in (?" + strings.Repeat(",?", len(groups)-1) + ")) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
		queryArgs = append(queryArgs, groupArgs...)
		queryArgs = append(queryArgs, accountID)
	} else {
		query = "select id, coalesce(uid_owner, '') as uid_owner, coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type, file_target from oc_share where (accepted=0 or accepted=1) and (share_type=? or share_type=? or share_type=?) and uid_owner!=? and (share_with=?) and id not in (select distinct(id) from oc_share_acl where rejected_by=?)"
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

func (sm *shareManager) getDBOCMShare(ctx context.Context, accountID, id string) (*dbShare, error) { //TODO !!!!!
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
	query := "select id, coalesce(uid_owner, '') as uid_owner,  coalesce(share_with, '') as share_with, coalesce(fileid_prefix, '') as fileid_prefix, coalesce(item_source, '') as item_source, stime, permissions, share_type from oc_share where uid_owner=? and (share_type=? or share_type=? or share_type=?) "
	params := []interface{}{accountID, 0, 1, 4}
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

func (sm *shareManager) convertToReceivedOCMShare(ctx context.Context, dbShare *dbShare, webdavUrl string) (*api.FolderShare, error) {
	l := ctx_zap.Extract(ctx)
	l.Info("CONVERTING TO OCM SHARE", zap.String("webdavUrl", webdavUrl), zap.String("Token", dbShare.Token), zap.String("FileTarget", dbShare.FileTarget))

	path := strings.Join([]string{"/ocm/" + webdavUrl, dbShare.Token, dbShare.FileTarget}, ";")
	share := &api.FolderShare{
		OwnerId:  dbShare.UIDOwner,
		Id:       fmt.Sprintf("%d", dbShare.ID),
		Mtime:    uint64(dbShare.STime),
		Path:     path,
		ReadOnly: dbShare.Permissions == 1,
		Recipient: &api.ShareRecipient{
			Identity: dbShare.ShareWith,
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

func (sm *shareManager) convertToOCMShare(ctx context.Context, dbShare *dbShare) (*api.OCMShare, error) { //TODO

	path := joinFileID(dbShare.Prefix, dbShare.ItemSource)
	share := &api.OCMShare{
		OwnerId:   dbShare.UIDOwner,
		Id:        fmt.Sprintf("%d", dbShare.ID),
		Mtime:     uint64(dbShare.STime),
		Path:      path,
		ReadOnly:  dbShare.Permissions == 1,
		Recipient: dbShare.ShareWith,
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

func (sm *shareManager) ListProviders(ctx context.Context) ([]*api.Provider, error) {

	dbProviders, err := sm.getDBOCMProviders(ctx)
	if err != nil {
		return nil, err
	}
	providers := []*api.Provider{}
	for _, dbProvider := range dbProviders {

		providers = append(providers, &api.Provider{
			Domain: dbProvider.Domain,
		})

	}
	return providers, nil
}
