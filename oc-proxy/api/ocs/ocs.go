package ocs

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cernbox/reva/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (p *proxy) registerRoutes() {
	// requests targeting a file/folder
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/shares", p.basicAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/shares", p.basicAuth(p.createShare)).Methods("POST")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/remote_shares", p.basicAuth(p.getRemoteShares)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/cernbox/ocs/v2.php/apps/files_sharing/api/v1/sharees", p.basicAuth(p.search)).Methods("GET")

	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/shares", p.basicAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/shares/pending/{share_id}", p.basicAuth(p.acceptShare)).Methods("POST")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/shares/pending/{share_id}", p.basicAuth(p.rejectShare)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/remote_shares", p.basicAuth(p.getRemoteShares)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/cernbox/ocs/v1.php/apps/files_sharing/api/v1/sharees", p.basicAuth(p.search)).Methods("GET")

	p.router.HandleFunc("/cernbox/index.php/apps/files_texteditor/ajax/loadfile", p.basicAuth(p.loadFile)).Methods("GET")
	p.router.HandleFunc("/cernbox/index.php/apps/files_texteditor/ajax/savefile", p.basicAuth(p.saveFile)).Methods("PUT")

	p.router.HandleFunc("/cernbox/index.php/apps/files/ajax/download.php", p.basicAuth(p.downloadArchive)).Methods("GET")

	p.router.HandleFunc("/cernbox/index.php/apps/eosinfo/getinfo", p.basicAuth(p.getEOSInfo)).Methods("POST")

	p.router.HandleFunc("/cernbox/index.php/apps/files_eostrashbin/ajax/list.php", p.basicAuth(p.listTrashbin)).Methods("GET")
	p.router.HandleFunc("/cernbox/index.php/apps/files_eostrashbin/ajax/undelete.php", p.basicAuth(p.restoreTrashbin)).Methods("POST")

	p.router.HandleFunc("/cernbox/index.php/apps/files_eosversions/ajax/getVersions.php", p.basicAuth(p.getVersions)).Methods("GET")
	p.router.HandleFunc("/cernbox/index.php/apps/files_eosversions/ajax/rollbackVersion.php", p.basicAuth(p.rollbackVersion)).Methods("GET")
	p.router.HandleFunc("/cernbox/index.php/apps/files_eosversions/download.php", p.basicAuth(p.downloadVersion)).Methods("GET")

}

/*
 {
            "id":"1",
            "share_type":3,
            "uid_owner":"admin",
            "displayname_owner":"admin",
            "permissions":1,
            "stime":1528476368,
            "parent":null,
            "expiration":null,
            "token":"wI9qedAsjltaihj",
            "uid_file_owner":"admin",
            "displayname_file_owner":"admin",
            "path":"\/Reverse cowgirl hotness.mp4",
            "item_type":"file",
            "mimetype":"video\/mp4",
            "storage_id":"home::admin",
            "storage":3,
            "item_source":82,
            "file_source":82,
            "file_parent":25,
            "file_target":"\/Reverse cowgirl hotness.mp4",
            "share_with":null,
            "share_with_displayname":null,
            "name":"Reverse cowgirl hotness.mp4 link",
            "url":"https:\/\/demo.owncloud.org\/s\/wI9qedAsjltaihj",
            "mail_send":0
         }
*/
type OCSShare struct {
	ID                   string     `json:"id"`
	ShareType            ShareType  `json:"share_type"`
	UIDOwner             string     `json:"uid_owner"`
	DisplayNameOwner     string     `json:"admin"`
	Permissions          Permission `json:"permissions"`
	ShareTime            int        `json:"stime"`
	Token                string     `json:"token"`
	UIDFileOwner         string     `json:"uid_file_owner"`
	DisplayNameFileOwner string     `json:"displayname_file_owner"`
	Path                 string     `json:"path"`
	ItemType             ItemType   `json:"item_type"`
	MimeType             string     `json:"mimetype"`
	ItemSource           string     `json:"item_source"`
	FileSource           string     `json:"file_source"`
	FileTarget           string     `json:"file_target"`
	ShareWith            string     `json:"share_with"`
	ShareWithDisplayName string     `json:"share_with_displayname"`
	Name                 string     `json:"name"`
	URL                  string     `json:"url"`
	State                ShareState `json:"state"`
	Expiration           string     `json:"expiration,omitempty"`
}

type NewShareOCSRequest struct {
	Path         string     `json:"path"`
	Name         string     `json:"name"`
	ShareType    ShareType  `json:"shareType"`
	ShareWith    string     `json:"shareWith"`
	PublicUpload bool       `json:"publicUpload"`
	Password     JSONString `json:"password"`
	Permissions  Permission `json:"permissions"`
	ExpireDate   JSONString `json:"expireDate"`
}

type Options struct {
	Logger *zap.Logger

	REVAHostname string
	REVAPort     int
	Router       *mux.Router

	CBOXGroupDaemonURI    string
	CBOXGroupDaemonSecret string
}

func (opt *Options) init() {
}

func New(opt *Options) (http.Handler, error) {
	if opt == nil {
		opt = &Options{}
	}

	opt.init()

	if opt.Router == nil {
		opt.Router = mux.NewRouter()
	}

	proxy := &proxy{
		router:                opt.Router,
		revaHost:              fmt.Sprintf("%s:%d", opt.REVAHostname, opt.REVAPort),
		logger:                opt.Logger,
		cboxGroupDaemonURI:    opt.CBOXGroupDaemonURI,
		cboxGroupDaemonSecret: opt.CBOXGroupDaemonSecret,
	}

	conn, err := grpc.Dial(proxy.revaHost, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	proxy.grpcConn = conn

	proxy.registerRoutes()
	return proxy, nil
}

type proxy struct {
	router                *mux.Router
	authClient            api.AuthClient
	revaHost              string
	cboxGroupDaemonURI    string
	cboxGroupDaemonSecret string
	grpcConn              *grpc.ClientConn
	logger                *zap.Logger
}

func (p *proxy) getStorageClient() api.StorageClient {
	return api.NewStorageClient(p.grpcConn)
}

func (p *proxy) getShareClient() api.ShareClient {
	return api.NewShareClient(p.grpcConn)
}

func (p *proxy) getAuthClient() api.AuthClient {
	return api.NewAuthClient(p.grpcConn)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

func (p *proxy) basicAuth(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		normalizedPath := mux.Vars(r)["path"]
		normalizedPath = path.Join("/", path.Clean(normalizedPath))
		mux.Vars(r)["path"] = normalizedPath

		authClient := p.getAuthClient()

		// try to get token from cookie
		authCookie, err := r.Cookie("oc_sessionpassphrase")
		if err == nil {
			token := authCookie.Value
			userRes, err := authClient.VerifyToken(ctx, &api.VerifyTokenReq{Token: token})
			if err != nil {
				p.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				if userRes.Status != api.StatusCode_OK {
					p.logger.Warn("cookie token is invalid or not longer valid", zap.Error(err))
				} else {
					user := userRes.User
					ctx = api.ContextSetUser(ctx, user)
					ctx = api.ContextSetAccessToken(ctx, token)
					r = r.WithContext(ctx)
					p.logger.Info("user authenticated with cookie", zap.String("account_id", user.AccountId))
					h(w, r)
					return
				}
			}

		} else {
			p.logger.Info("cookie oc_sessionpassphrase not set")
		}

		// try to get credentials using basic auth
		username, password, ok := r.BasicAuth()
		if !ok {
			p.logger.Info("basic auth not provided")
			w.Header().Set("WWW-Authenticate", "Basic Realm='owncloud credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// try to authenticate user with username and password
		gReq := &api.CreateTokenReq{ClientId: username, ClientSecret: password}
		gTokenRes, err := authClient.CreateToken(ctx, gReq)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return

		}
		if gTokenRes.Status != api.StatusCode_OK {
			p.logger.Warn("token is not valid", zap.Int("status", int(gTokenRes.Status)))
			w.Header().Set("WWW-Authenticate", "Basic Realm='owncloud credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := gTokenRes.Token
		p.logger.Info("token created", zap.String("token", token.Token))

		gReq2 := &api.VerifyTokenReq{Token: token.Token}
		userRes, err := authClient.VerifyToken(ctx, gReq2)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if userRes.Status != api.StatusCode_OK {
			p.logger.Error("", zap.Error(err))
			w.Header().Set("WWW-Authenticate", "Basic Realm='owncloud credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// save token into cookie for further requests
		cookie := &http.Cookie{}
		cookie.Name = "oc_sessionpassphrase"
		cookie.Value = token.Token
		cookie.MaxAge = 3600
		http.SetCookie(w, cookie)

		user := userRes.User
		ctx = api.ContextSetUser(ctx, user)
		ctx = api.ContextSetAccessToken(ctx, token.Token)
		r = r.WithContext(ctx)

		p.logger.Info("request is authenticated", zap.String("account_id", user.AccountId))
		h.ServeHTTP(w, r)
	})
}

func (p *proxy) downloadVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filename := r.URL.Query().Get("file")
	revision := r.URL.Query().Get("revision")

	if filename == "" || revision == "" {
		p.logger.Warn("missing params", zap.String("file", filename), zap.String("revision", revision))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gCtx := GetContextWithAuth(ctx)

	_, err := p.getMetadata(ctx, filename)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	stream, err := p.getStorageClient().ReadRevision(gCtx, &api.RevisionReq{Path: filename, RevKey: revision})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+path.Base(filename))
	w.WriteHeader(http.StatusOK)
	var reader io.Reader
	for {
		dcRes, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if dcRes.Status != api.StatusCode_OK {
			p.writeError(dcRes.Status, w, r)
			return
		}

		dc := dcRes.DataChunk

		if dc != nil {
			if dc.Length > 0 {
				reader = bytes.NewReader(dc.Data)
				_, err := io.CopyN(w, reader, int64(dc.Length))
				if err != nil {
					p.logger.Error("", zap.Error(err))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
		}
	}
}

/*
{
   "data":{
      "revision":"1529574036.646df75d",
      "file":"\/ideas\/hello.txt"
   },
   "status":"success"
}
*/
type rollbackVersionRes struct {
	Data struct {
		Revision string
		File     string
	}
	Status string
}

func (p *proxy) rollbackVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filename := r.URL.Query().Get("file")
	revision := r.URL.Query().Get("revision")

	if filename == "" || revision == "" {
		p.logger.Warn("missing params", zap.String("file", filename), zap.String("revision", revision))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gCtx := GetContextWithAuth(ctx)
	res, err := p.getStorageClient().RestoreRevision(gCtx, &api.RevisionReq{Path: filename, RevKey: revision})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != api.StatusCode_OK {
		err := api.NewError(api.UnknownError)
		p.logger.Error("", zap.Error(err))
		return
	}

	resp := &rollbackVersionRes{Status: "success", Data: struct {
		Revision string
		File     string
	}{revision, filename}}

	encoded, err := json.Marshal(resp)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

/*
{
  "data": {
    "versions": {
      "1529501898.64217314#/3769_001.pdf": {
        "eos.size": "226665",
        "eos.mtime": "1529501898",
        "eos.ctime": "1529501898.117864887",
        "eos.mode": "0644",
        "eos.uid": "95491",
        "eos.gid": "2763",
        "eos.fxid": "64217314",
        "eos.fid": "1679913748",
        "eos.ino": "450948412985049088",
        "eos.pid": "96056290",
        "eos.pxid": "05b9b3e2",
        "eos.xstype": "adler",
        "eos.xs": "51163093",
        "eos.etag": "450948412985049088:51163093",
        "eos.layout": "replica",
        "eos.nstripes": "2",
        "eos.lid": "00600112",
        "eos.nrep": "2",
        "eos.fsid": "1030",
        "eos.file": "/eos/user/g/gonzalhu/.sys.v#.3769_001.pdf/1529501898.64217314",
        "etag": "450948412985049088:51163093",
        "fileid": 450948412985049100,
        "mtime": 1529501898,
        "size": "226665",
        "storage_mtime": 1529501898,
        "path": "/3769_001.pdf",
        "path_hash": "3bb79fa07612f1c538302dd35198e120",
        "parent": 96056290,
        "encrypted": 0,
        "unencrypted_size": "226665",
        "name": "3769_001.pdf",
        "mimetype": "application/octet-stream",
        "permissions": 31,
        "current_revision_path": "files/3769_001.pdf",
        "revision": "1529501898.64217314",
        "cur": 0,
        "version": "1529501898.64217314"
      }
    },
    "endReached": true
  },
  "status": "success"
}
*/
type getVersionsRes struct {
	Status string       `json:"status"`
	Data   *versionsRes `json:"data"`
}
type versionsRes struct {
	Versions map[string]*versionEntry `json:"versions"`
}

type versionEntry struct {
	Revision string `json:"revision"`
	Version  string `json:"version"`
	Name     string `json:"name"`
	MTime    int64  `json:"mtime"`
	Size     int    `json:"size"`
}

func (p *proxy) getVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := r.URL.Query().Get("source")
	if path == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	revisions, err := p.getVersionsForPath(ctx, path)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ocRevisions := map[string]*versionEntry{}
	for _, r := range revisions {
		e := &versionEntry{
			Revision: r.RevKey,
			Name:     path,
			Size:     int(r.Size),
			Version:  r.RevKey,
			MTime:    int64(r.Mtime),
		}
		key := fmt.Sprintf("%s/%s", path, e.Revision)
		ocRevisions[key] = e
	}

	payload := &versionsRes{Versions: ocRevisions}
	res := &getVersionsRes{Data: payload, Status: "success"}
	encoded, err := json.Marshal(res)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

func (p *proxy) getVersionsForPath(ctx context.Context, path string) ([]*api.Revision, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getStorageClient().ListRevisions(gCtx, &api.PathReq{Path: path})
	if err != nil {
		return nil, err
	}

	revisions := []*api.Revision{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != api.StatusCode_OK {
			err := api.NewError(api.UnknownError)
			return nil, err
		}
		revisions = append(revisions, res.Revision)
	}
	return revisions, nil
}

/*
{
   "ocs":{
      "meta":{
         "status":"ok",
         "statuscode":100,
         "message":"OK",
         "totalitems":"",
         "itemsperpage":""
      },
      "data":{
         "exact":{
            "users":[

            ],
            "groups":[

            ],
            "remotes":[

            ]
         },
         "users":[
            {
               "label":"Hugo Gonzalez Labrador (gonzalhu)",
               "value":{
                  "shareType":0,
                  "shareWith":"gonzalhu"
               }
            }
         ],
         "groups":[
            {
               "label":"cernbox-project-labradorprojecttest-admins",
               "value":{
                  "shareType":1,
                  "shareWith":"cernbox-project-labradorprojecttest-admins"
               }
            },
            {
               "label":"cernbox-project-labradorprojecttest-writers",
               "value":{
                  "shareType":1,
                  "shareWith":"cernbox-project-labradorprojecttest-writers"
               }
            },
            {
               "label":"cernbox-project-labradorprojecttest-readers",
               "value":{
                  "shareType":1,
                  "shareWith":"cernbox-project-labradorprojecttest-readers"
               }
            }
         ],
         "remotes":[

         ]
      }
   }
}
*/

type OCSShareeData struct {
	Exact   *OCSShareeExact   `json:"exact"`
	Users   []*OCSShareeEntry `json:"users"`
	Groups  []*OCSShareeEntry `json:"groups"`
	Remotes []*OCSShareeEntry `json:"remotes"`
}
type OCSShareeExact struct {
	Users   []*OCSShareeEntry `json:"users"`
	Groups  []*OCSShareeEntry `json:"groups"`
	Remotes []*OCSShareeEntry `json:"remotes"`
}

type OCSShareeEntry struct {
	Label string               `json:"label"`
	Value *OCSShareeEntryValue `json:"value"`
}

type OCSShareeEntryValue struct {
	ShareType ShareType `json:"shareType"`
	ShareWith string    `json:"shareWith"`
}

type LoadFileResponse struct {
	FileContents string `json:"filecontents"`
	Writable     bool   `json:"writeable"`
	Mime         string `json:"mime"`
	MTime        int    `json:"mtime"`
}

type SaveFileResponse struct {
	Size  int `json:"size"`
	Mtime int `json:"mtime"`
}

type WalkFunc func(path string, md *api.Metadata, err error) error

var SkipDir = errors.New("skip this directory")

func (p *proxy) Walk(ctx context.Context, root string, walkFn WalkFunc) error {
	md, err := p.getMetadata(ctx, root)
	if err != nil {
		err = walkFn(root, nil, err)
	} else {
		err = p.walkRecursive(ctx, root, md, walkFn)
	}

	if err == SkipDir {
		return nil
	}
	return err
}

// readDirNames reads the directory named by dirname and returns
// a sorted list of directory entries.
func (p *proxy) readDirNames(ctx context.Context, dirname string) ([]string, error) {
	names := []string{}

	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getStorageClient().ListFolder(gCtx, &api.PathReq{Path: dirname})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		return names, err
	}

	for {
		mdRes, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			p.logger.Error("", zap.Error(err))
			return names, err
		}
		if mdRes.Status != api.StatusCode_OK {
			p.logger.Error("", zap.Int("status", int(mdRes.Status)))
			return names, err
		}
		names = append(names, mdRes.Metadata.Path)
	}

	sort.Strings(names)
	return names, nil
}

// walk recursively descends path, calling walkFn.
func (p *proxy) walkRecursive(ctx context.Context, path string, md *api.Metadata, walkFn WalkFunc) error {
	if !md.IsDir {
		return walkFn(path, md, nil)
	}

	names, err := p.readDirNames(ctx, path)
	err1 := walkFn(path, md, err)
	// If err != nil, walk can't walk into this directory.
	// err1 != nil means walkFn want walk to skip this directory or stop walking.
	// Therefore, if one of err and err1 isn't nil, walk will return.
	if err != nil || err1 != nil {
		// The caller's behavior is controlled by the return value, which is decided
		// by walkFn. walkFn may ignore err and return nil.
		// If walkFn returns SkipDir, it will be handled by the caller.
		// So walk should return whatever walkFn returns.
		return err1
	}

	for _, filename := range names {
		//filename := Join(path, name)

		//fileInfo, err := lstat(filename)
		md, err := p.getMetadata(ctx, filename)
		if err != nil {
			if err := walkFn(filename, md, err); err != nil && err != SkipDir {
				return err
			}
		} else {
			err = p.walkRecursive(ctx, filename, md, walkFn)
			if err != nil {
				if !md.IsDir || err != SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

func (p *proxy) getMetadata(ctx context.Context, path string) (*api.Metadata, error) {
	gCtx := GetContextWithAuth(ctx)
	mdRes, err := p.getStorageClient().Inspect(gCtx, &api.PathReq{Path: path})
	if err != nil {
		p.logger.Error("", zap.Error(err), zap.String("path", path))
		return nil, err
	}
	if mdRes.Status != api.StatusCode_OK {
		p.logger.Error("", zap.Int("status", int(mdRes.Status)), zap.String("path", path))
		// TODO(labkode): set better error code
		return nil, api.NewError(api.StorageNotSupportedErrorCode).WithMessage(fmt.Sprintf("status: %d", mdRes.Status))
	}
	return mdRes.Metadata, nil
}

/*
GET http://labradorbox.cern.ch/cernbox/index.php/apps/files/ajax/download.php?dir=/&files[]=welcome.txt&files[]=signed contract.pdf&files[]=peter.txt&downloadStartSecret=k9ubkisonib HTTP/1.1
Creates a TAR archive
*/
func (p *proxy) downloadArchive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dir := r.URL.Query().Get("dir")
	files := []string{}

	if dir == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("files") != "" {
		fullPath := path.Join(dir, r.URL.Query().Get("files"))
		files = append(files, fullPath)
	} else {
		fileList := r.URL.Query()["files[]"]
		for _, fn := range fileList {
			fullPath := path.Join(dir, fn)
			files = append(files, fullPath)

		}
	}

	// if files is empty means that we need to download the whole content of dir
	if len(files) == 0 {
		files = append(files, dir)
	}

	// TODO(labkode): add request ID to the archive name so we can trace back archive.
	archiveName := "download.tar"
	if len(files) == 1 {
		archiveName = path.Base(files[0]) + ".tar"
	}

	p.logger.Debug("archive name: " + archiveName)

	// TODO(labkode): check for size because once the data is being written to the client we cannot override the headers.

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", archiveName))
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	gCtx := GetContextWithAuth(ctx)

	tw := tar.NewWriter(w)
	defer tw.Close()
	for _, fn := range files {
		err := p.Walk(ctx, fn, func(path string, md *api.Metadata, err error) error {
			if err != nil {
				return err
			}

			p.logger.Debug("walking", zap.String("filename", path))
			hdr := &tar.Header{
				Name:    md.Path,
				Mode:    0600,
				Size:    int64(md.Size),
				ModTime: time.Unix(int64(md.Mtime), 0),
			}

			if md.IsDir {
				hdr.Typeflag = tar.TypeDir
				hdr.Mode = 0755
			}

			if err := tw.WriteHeader(hdr); err != nil {
				p.logger.Error("", zap.Error(err), zap.String("fn", fn))
				return err
			}

			// if file, write file contents into the tar archive
			if !md.IsDir {

				stream, err := p.getStorageClient().ReadFile(gCtx, &api.PathReq{Path: md.Path})
				if err != nil {
					p.logger.Error("", zap.Error(err))
					return err
				}

				for {
					dcRes, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						p.logger.Error("", zap.Error(err))
						return err
					}
					if dcRes.Status != api.StatusCode_OK {
						p.logger.Error("", zap.Int("status", int(dcRes.Status)))
						return api.NewError(api.StorageNotSupportedErrorCode)
					}

					dc := dcRes.DataChunk

					if dc != nil {
						if dc.Length > 0 {
							if _, err := tw.Write(dc.Data); err != nil {
								p.logger.Error("", zap.Error(err))
								return err
							}
						}
					}
				}

			} else {
				return nil

			}
		})

		if err != nil {
			p.logger.Error("", zap.Error(err))
		}
	}

}

/*
{
   "eos-instance":"root:\/\/eosuser-internal.cern.ch",
   "eos-file":"\/eos\/user\/g\/gonzalhu\/University"
}
*/
func (p *proxy) getEOSInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := r.ParseForm()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	path := r.Form.Get("path")
	md, err := p.getMetadata(ctx, path)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data := &struct {
		EosInstance string `json:"eos-instance"`
		EosFile     string `json:"eos-file"`
	}{EosInstance: md.EosInstance, EosFile: md.EosFile}

	encoded, err := json.Marshal(data)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

/*
{
   "data":{
      "permissions":0,
      "directory":"\/",
      "files":[
         {
            "eos.recycle":"ls",
            "eos.recycle-bin":"\/eos\/uat\/proc\/recycle\/",
            "eos.uid":"gonzalhu",
            "eos.gid":"it",
            "eos.size":"0",
            "eos.deletion-time":1529487461000,
            "eos.type":"recursive-dir",
            "eos.keylength.restore-path":"72",
            "eos.restore-path":"\/eos\/scratch\/user\/g\/gonzalhu\/Images\/Ourense\/Pozas\/Ceo\/.sys.v#.hello.txt\/",
            "eos.restore-key":"00000000005d2688",
            "path":"files\/Images\/Ourense\/Pozas\/Ceo\/.sys.v#.hello.txt",
            "name":".sys.v#.hello.txt",
            "mtime":1529487461000,
            "id":0,
            "permissions":1,
            "mimetype":"httpd\/unix-directory"
         },
         {
            "eos.recycle":"ls",
            "eos.recycle-bin":"\/eos\/uat\/proc\/recycle\/",
            "eos.uid":"gonzalhu",
            "eos.gid":"it",
            "eos.size":"283115530",
            "eos.deletion-time":1529487461000,
            "eos.type":"recursive-dir",
            "eos.keylength.restore-path":"35",
            "eos.restore-path":"\/eos\/scratch\/user\/g\/gonzalhu\/Images",
            "eos.restore-key":"00000000005d1432",
            "path":"files\/Images",
            "name":"Images",
            "mtime":1529487461000,
            "id":1,
            "permissions":1,
            "mimetype":"httpd\/unix-directory"
         }
      ]
   },
   "status":"success"
}
*/
type trashbinEntry struct {
	EosRestoreKey  string `json:"eos.restore-key"`
	EosRestorePath string `json:"eos.restore-path"`
	ID             string `json:"id"`
	Mimetype       string `json:"mimetype"`
	Mtime          int    `json:"mtime"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	Permissions    int    `json:"permissions"`
	Size           int    `json:"size"`
}

type listTrashbinRes struct {
	Data   *listTrashbinData `json:"data"`
	Status string            `json:"status"`
}

type listTrashbinData struct {
	Directory   string           `json:"directory"`
	Files       []*trashbinEntry `json:"files"`
	Permissions int              `json:"permissions"`
}

func (p *proxy) listTrashbin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getStorageClient().ListRecycle(gCtx, &api.PathReq{Path: "/"})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	entries := []*api.RecycleEntry{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if res.Status != api.StatusCode_OK {
			err := api.NewError(api.UnknownError)
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		entries = append(entries, res.RecycleEntry)
	}

	trashbinEntries := []*trashbinEntry{}
	for _, e := range entries {
		te := &trashbinEntry{
			ID:          e.RestoreKey,
			Path:        e.RestorePath,
			Permissions: 0,
			Name:        path.Base(e.RestorePath),
			Mimetype:    p.detectMimeType(e.IsDir, e.RestorePath),
			Mtime:       int(e.DelMtime) * 1000, // oc expects 13 digit
			Size:        int(e.Size),
			// TODO(labkode): refactor trashbin app to not rely on these attributes.
			EosRestoreKey:  e.RestoreKey,
			EosRestorePath: e.RestorePath,
		}
		trashbinEntries = append(trashbinEntries, te)
	}

	payload := &listTrashbinRes{
		Status: "success",
		Data:   &listTrashbinData{Directory: "/", Files: trashbinEntries, Permissions: 0},
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

func (p *proxy) restoreTrashbin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := r.ParseForm()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	restoreAllFiles := r.Form.Get("allfiles") == "true"
	if restoreAllFiles {
		p.restoreAllFiles(w, r)
		return
	}

	/*
		files is this string, not a real array, so we can treat it as json and marshal into struct
		["Questions.md.home:0000000004bc4f35","Desktop.home:00000000005d3118"]
	*/
	filesAsString := r.Form.Get("files")
	files := []string{}
	err = json.Unmarshal([]byte(filesAsString), &files)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	now := time.Now().Unix()
	restoredEntries := []*restoredEntry{}
	failedEntries := []*restoredEntry{}
	for _, f := range files {
		tokens := strings.Split(f, ".")
		// the token after the last . is the restore key
		if len(tokens) == 0 {
			err := api.NewError(api.UnknownError).WithMessage(fmt.Sprintf("restore key is invalid. tokens: %+v", tokens))
			p.logger.Error("", zap.Error(err))
			failedEntries = append(failedEntries, &restoredEntry{Filename: f, Timestamp: now})
			continue

		} else {
			restoreKey := tokens[len(tokens)-1]
			if err := p.restoreRecycleEntry(ctx, restoreKey); err != nil {
				p.logger.Error("", zap.Error(err))
				failedEntries = append(failedEntries, &restoredEntry{Filename: f, Timestamp: now})
				continue
			} else {
				restoredEntries = append(restoredEntries, &restoredEntry{Filename: f, Timestamp: now})
			}

		}
	}

	res := &restoreResponse{Status: "success", Data: &restoreData{Success: restoredEntries}}
	encoded, err := json.Marshal(res)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

func (p *proxy) getRecycleEntries(ctx context.Context) ([]*api.RecycleEntry, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getStorageClient().ListRecycle(gCtx, &api.PathReq{Path: "/"})
	if err != nil {
		return nil, err
	}

	entries := []*api.RecycleEntry{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != api.StatusCode_OK {
			err := api.NewError(api.UnknownError)
			return nil, err
		}
		entries = append(entries, res.RecycleEntry)
	}
	return entries, nil
}

/*
{
  "data": {
    "success": [
      {
        "filename": "gantt.png.00000000620dbf7b",
        "timestamp": 1529498980
      }
    ]
  },
  "status": "success"
*/
type restoreResponse struct {
	Status string       `json:"status"`
	Data   *restoreData `json:"data"`
}

type restoreData struct {
	Success []*restoredEntry `json:"success"`
}

type restoredEntry struct {
	Filename  string `json:"filename"`
	Timestamp int64  `json:"timestamp"`
}

func (p *proxy) restoreAllFiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entries, err := p.getRecycleEntries(ctx)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	now := time.Now().Unix()
	restoredEntries := []*restoredEntry{}
	failedEntries := []*restoredEntry{}
	for _, e := range entries {
		entry := &restoredEntry{Filename: e.RestorePath, Timestamp: now}
		err := p.restoreRecycleEntry(ctx, e.RestoreKey)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			// dont' abort request and restore as many files as we can
			failedEntries = append(failedEntries, entry)
			continue
		}
		restoredEntries = append(restoredEntries, entry)
	}

	res := &restoreResponse{Status: "success", Data: &restoreData{Success: restoredEntries}}
	encoded, err := json.Marshal(res)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

func (p *proxy) restoreRecycleEntry(ctx context.Context, restoreKey string) error {
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getStorageClient().RestoreRecycleEntry(gCtx, &api.RecycleEntryReq{RestoreKey: restoreKey})
	if err != nil {
		return err
	}

	if res.Status != api.StatusCode_OK {
		return api.NewError(api.UnknownError).WithMessage(fmt.Sprintf("status: %d", res.Status))

	}
	return nil
}

/* This is x-www-form-urlencoded request

filecontents: Welcome to your ownCloud account!
path: /welcome.txt
mtime: 1528881571

*/
func (p *proxy) saveFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := r.ParseForm()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fileContents := r.Form.Get("filecontents")
	//mtime := r.Form.Get("mtime")
	path := r.Form.Get("path")

	md, err := p.getMetadata(ctx, path)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO(labkode): check that sent mtime is bigger than stored one, else means a conflict and we do not override :)

	gCtx := GetContextWithAuth(ctx)
	txInfoRes, err := p.getStorageClient().StartWriteTx(gCtx, &api.EmptyReq{})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if txInfoRes.Status != api.StatusCode_OK {
		p.writeError(txInfoRes.Status, w, r)
		return
	}

	txInfo := txInfoRes.TxInfo

	stream, err := p.getStorageClient().WriteChunk(gCtx)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO(labkode); adjust buffer size to maximun opening file fize
	buffer := make([]byte, 1024*1024*3)
	offset := uint64(0)
	numChunks := uint64(0)

	reader := bytes.NewReader([]byte(fileContents))
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			dc := &api.TxChunk{
				TxId:   txInfo.TxId,
				Length: uint64(n),
				Data:   buffer,
				Offset: offset,
			}
			if err := stream.Send(dc); err != nil {
				p.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			numChunks++
			offset += uint64(n)

		}
		if err == io.EOF {
			break
		}
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	writeSummaryRes, err := stream.CloseAndRecv()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if writeSummaryRes.Status != api.StatusCode_OK {
		p.writeError(writeSummaryRes.Status, w, r)
		return
	}

	// all the chunks have been sent, we need to close the tx
	emptyRes, err := p.getStorageClient().FinishWriteTx(gCtx, &api.TxEnd{Path: path, TxId: txInfo.TxId})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if emptyRes.Status != api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	md, err = p.getMetadata(ctx, path)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := &SaveFileResponse{Mtime: int(md.Mtime), Size: int(md.Size)}
	encoded, err := json.Marshal(res)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

/*
{"filecontents":"","writeable":true,"mime":"text\/plain","mtime":1528905319}
*/
func (p *proxy) loadFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dir := r.URL.Query().Get("dir")
	filename := r.URL.Query().Get("filename")
	fullPath := path.Join(dir, filename)

	md, err := p.getMetadata(ctx, fullPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	gCtx := GetContextWithAuth(ctx)
	pathReq := &api.PathReq{Path: fullPath}

	stream, err := p.getStorageClient().ReadFile(gCtx, pathReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO(labkode): stop loading huge files, set max to 1mib?

	fileContents := []byte{}
	for {
		dcRes, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if dcRes.Status != api.StatusCode_OK {
			p.writeError(dcRes.Status, w, r)
			return
		}

		dc := dcRes.DataChunk

		if dc != nil {
			if dc.Length > 0 {
				fileContents = append(fileContents, dc.Data...)
			}
		}
	}

	// TODO(labkode): specify permission at the metadata response
	mime := p.detectMimeType(md.IsDir, fullPath)
	res := &LoadFileResponse{
		FileContents: string(fileContents),
		MTime:        int(md.Mtime),
		Mime:         mime,
		Writable:     true,
	}

	encoded, err := json.Marshal(res)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

type searchEntry struct {
	DN          string          `json:"dn"`
	CN          string          `json:"cn"`
	AccountType LDAPAccountType `json:"account_type"`
	DisplayName string          `json:"display_name"`
	Mail        string          `json:"mail"`
}

func (p *proxy) getShareType(ldapType LDAPAccountType) ShareType {
	if ldapType == LDAPAccountTypePrimary || ldapType == LDAPAccountTypeSecondary || ldapType == LDAPAccountTypeService {
		return ShareTypeUser
	} else if ldapType == LDAPAccountTypeEGroup || ldapType == LDAPAccountTypeEGroup {
		return ShareTypeGroup
	} else {
		// fallback to user
		return ShareTypeUser
	}
}
func (p *proxy) getSearchTarget(search string) string {
	tokens := strings.Split(search, ":")
	if len(tokens) == 0 {
		return tokens[0]
	} else {
		return tokens[len(tokens)-1]
	}
}

// search calls the cboxgroupd daemon for finding entries.
func (p *proxy) search(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")

	//itemType := r.URL.Query().Get("itemType")
	//perPage := r.URL.Query().Get("perPage")

	if search == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	searchTarget := p.getSearchTarget(search)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/api/v1/search/%s", p.cboxGroupDaemonURI, search)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.cboxGroupDaemonSecret))
	res, err := client.Do(req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.StatusCode != http.StatusOK {
		p.logger.Error("error calling cboxgroupd search", zap.Int("status", res.StatusCode))
		w.WriteHeader(res.StatusCode)
		return

	}

	searchEntries := []*searchEntry{}
	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(res.StatusCode)
		return
	}

	err = json.Unmarshal(body, &searchEntries)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	exactUserEntries := []*OCSShareeEntry{}
	inexactUserEntries := []*OCSShareeEntry{}
	exactGroupEntries := []*OCSShareeEntry{}
	inexactGroupEntries := []*OCSShareeEntry{}
	for _, se := range searchEntries {
		shareType := p.getShareType(se.AccountType)
		ocsEntry := &OCSShareeEntry{
			Value: &OCSShareeEntryValue{ShareType: p.getShareType(se.AccountType), ShareWith: se.CN},
		}

		if shareType == ShareTypeUser {
			ocsEntry.Label = fmt.Sprintf("%s (%s)", se.DisplayName, se.CN)
			if se.CN == searchTarget {
				exactUserEntries = append(exactUserEntries, ocsEntry)
			} else {
				inexactUserEntries = append(inexactUserEntries, ocsEntry)
			}

		} else { // asumme group
			ocsEntry.Label = se.CN // owncloud will append (group) at the end
			if se.CN == searchTarget {
				exactGroupEntries = append(exactGroupEntries, ocsEntry)
			} else {
				inexactGroupEntries = append(inexactGroupEntries, ocsEntry)
			}

		}

	}

	exact := &OCSShareeExact{Users: exactUserEntries, Groups: exactGroupEntries, Remotes: []*OCSShareeEntry{}}
	data := &OCSShareeData{Exact: exact, Users: inexactUserEntries, Groups: inexactGroupEntries, Remotes: []*OCSShareeEntry{}}

	meta := &ResponseMeta{Status: "ok", StatusCode: 100, Message: "OK"}
	payload := &OCSPayload{Meta: meta, Data: data}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

func (p *proxy) createPublicLinkShare(newShare *NewShareOCSRequest, readOnly bool, expiration int64, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	gCtx := GetContextWithAuth(ctx)
	newLinkReq := &api.NewLinkReq{
		Path:     newShare.Path,
		ReadOnly: readOnly,
		Password: newShare.Password.Value,
		Expires:  uint64(expiration),
	}
	publicLinkRes, err := p.getShareClient().CreatePublicLink(gCtx, newLinkReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if publicLinkRes.Status != api.StatusCode_OK {
		p.writeError(publicLinkRes.Status, w, r)
		return
	}

	publicLink := publicLinkRes.PublicLink
	ocsShare, err := p.publicLinkToOCSShare(ctx, publicLink)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	meta := &ResponseMeta{Status: "ok", StatusCode: 200}
	payload := &OCSPayload{Meta: meta, Data: ocsShare}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

func (p *proxy) createFolderShare(newShare *NewShareOCSRequest, readOnly bool, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	recipientType := api.ShareRecipient_USER
	if newShare.ShareType == ShareTypeGroup {
		recipientType = api.ShareRecipient_GROUP
	}

	recipient := &api.ShareRecipient{
		Identity: newShare.ShareWith,
		Type:     recipientType,
	}

	newFolderShareReq := &api.NewFolderShareReq{
		Path:      newShare.Path,
		ReadOnly:  readOnly,
		Recipient: recipient,
	}

	gCtx := GetContextWithAuth(ctx)
	folderShareRes, err := p.getShareClient().AddFolderShare(gCtx, newFolderShareReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if folderShareRes.Status != api.StatusCode_OK {
		p.writeError(folderShareRes.Status, w, r)
		return
	}

	folderShare := folderShareRes.FolderShare
	ocsShare, err := p.folderShareToOCSShare(ctx, folderShare)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	meta := &ResponseMeta{Status: "ok", StatusCode: 200}
	payload := &OCSPayload{Meta: meta, Data: ocsShare}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}
func (p *proxy) createShare(w http.ResponseWriter, r *http.Request) {
	newShare := &NewShareOCSRequest{}

	if r.Header.Get("Content-Type") == "application/json" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = json.Unmarshal(body, newShare)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else { // assume x-www-form-urlencoded
		err := r.ParseForm()
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		shareTypeString := r.Form.Get("shareType")
		shareWith := r.Form.Get("shareWith")
		permissionsString := r.Form.Get("permissions")
		path := r.Form.Get("path")

		var shareType ShareType
		var permissions Permission
		if shareTypeString == "0" {
			shareType = ShareTypeUser
		} else if shareTypeString == "1" {
			shareType = ShareTypeGroup
		}

		perm, err := strconv.ParseInt(permissionsString, 10, 64)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		permissions = Permission(perm)

		newShare.Path = path
		newShare.ShareWith = shareWith
		newShare.ShareType = shareType
		newShare.Permissions = permissions

	}

	var readOnly bool
	if newShare.Permissions == PermissionRead {
		readOnly = true
	}

	var expiration int64
	if newShare.ExpireDate.Set && newShare.ExpireDate.Value != "" {
		t, err := time.Parse("02-01-2006", newShare.ExpireDate.Value)
		if err != nil {
			p.logger.Error("expire data format is not valid", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		expiration = t.Unix()
	}

	if newShare.ShareType == ShareTypePublicLink {
		p.createPublicLinkShare(newShare, readOnly, expiration, w, r)
		return
	} else if newShare.ShareType == ShareTypeUser || newShare.ShareType == ShareTypeGroup {
		p.createFolderShare(newShare, readOnly, w, r)
		return
	} else {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

}

func (p *proxy) getRemoteShares(w http.ResponseWriter, r *http.Request) {
	shares := []*OCSShare{}
	meta := &ResponseMeta{Status: "ok", StatusCode: 100}
	payload := &OCSPayload{Meta: meta, Data: shares}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

func (p *proxy) getShares(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := r.URL.Query().Get("path")
	sharedWithMe := r.URL.Query().Get("shared_with_me")

	if sharedWithMe == "true" {
		p.getReceivedShares(w, r, path)
		return
	}

	ocsShares, err := p.getPublicLinkShares(ctx)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	folderShares, err := p.getFolderShares(ctx)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return

	}

	ocsShares = append(ocsShares, folderShares...)
	meta := &ResponseMeta{Status: "ok", StatusCode: 200}
	payload := &OCSPayload{Meta: meta, Data: ocsShares}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

func (p *proxy) getPublicLinkShares(ctx context.Context) ([]*OCSShare, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getShareClient().ListPublicLinks(gCtx, &api.EmptyReq{})
	if err != nil {
		return nil, err
	}

	publicLinks := []*api.PublicLink{}
	for {
		plr, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if plr.Status != api.StatusCode_OK {
			return nil, err
		}
		publicLinks = append(publicLinks, plr.PublicLink)

	}

	ocsShares := []*OCSShare{}
	for _, pl := range publicLinks {
		ocsShare, err := p.publicLinkToOCSShare(ctx, pl)
		if err != nil {
			p.logger.Error("cannot convert public link to ocs share", zap.Error(err), zap.String("pl", fmt.Sprintf("%+v", pl)))
			continue
		}
		ocsShares = append(ocsShares, ocsShare)
	}
	return ocsShares, nil

}

func (p *proxy) getFolderShares(ctx context.Context) ([]*OCSShare, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getShareClient().ListFolderShares(gCtx, &api.ListFolderSharesReq{})
	if err != nil {
		return nil, err
	}

	folderShares := []*api.FolderShare{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != api.StatusCode_OK {
			return nil, err
		}
		folderShares = append(folderShares, res.FolderShare)

	}

	ocsShares := []*OCSShare{}
	for _, share := range folderShares {
		ocsShare, err := p.folderShareToOCSShare(ctx, share)
		if err != nil {
			p.logger.Error("cannot convert folder share to ocs share", zap.Error(err), zap.String("folder share", fmt.Sprintf("%+v", share)))
			continue
		}
		ocsShares = append(ocsShares, ocsShare)
	}
	return ocsShares, nil

}

func (p *proxy) folderShareToOCSShare(ctx context.Context, share *api.FolderShare) (*OCSShare, error) {
	fmt.Println("folder share IN", share)
	// TODO(labkode): harden check
	user, _ := api.ContextGetUser(ctx)
	owner := user.AccountId

	md, err := p.getMetadata(ctx, share.Path)
	if err != nil {
		return nil, err
	}

	var itemType ItemType = ItemTypeFolder
	shareType := ShareTypeUser
	if share.Recipient.Type == api.ShareRecipient_GROUP {
		shareType = ShareTypeGroup
	}

	var mimeType = "httpd/unix-directory"
	var permissions Permission
	if share.ReadOnly {
		permissions = PermissionRead
	} else {
		permissions = PermissionReadWrite
	}

	var shareWith string = share.Recipient.Identity

	ocsShare := &OCSShare{
		ShareType:            shareType,
		ID:                   share.Id,
		DisplayNameFileOwner: owner,
		DisplayNameOwner:     owner,
		FileSource:           share.Path,
		FileTarget:           share.Path,
		ItemSource:           share.Path,
		ItemType:             itemType,
		MimeType:             mimeType,
		Name:                 share.Path,
		Path:                 md.Path,
		Permissions:          permissions,
		ShareTime:            int(share.Mtime),
		State:                ShareStateAccepted,
		UIDFileOwner:         owner,
		UIDOwner:             owner,
		ShareWith:            shareWith,
		ShareWithDisplayName: shareWith,
	}
	fmt.Println("folder share OUT ", ocsShare)
	return ocsShare, nil
}
func (p *proxy) publicLinkToOCSShare(ctx context.Context, pl *api.PublicLink) (*OCSShare, error) {
	// TODO(labkode): harden check
	user, _ := api.ContextGetUser(ctx)
	owner := user.AccountId

	md, err := p.getMetadata(ctx, pl.Path)
	if err != nil {
		return nil, err
	}

	var itemType ItemType
	if pl.ItemType == api.PublicLink_FOLDER {
		itemType = ItemTypeFolder
	} else {
		itemType = ItemTypeFile
	}

	var mimeType string
	if pl.ItemType == api.PublicLink_FOLDER {
		mimeType = "httpd/unix-directory"
	} else {
		mimeType = mime.TypeByExtension(path.Ext(pl.Path))
	}
	var permissions Permission
	if pl.ReadOnly {
		permissions = PermissionRead
	} else {
		permissions = PermissionReadWrite
	}

	var shareWith string
	if pl.Protected {
		shareWith = "X"
	}

	var expiration string
	if pl.Expires > 0 {
		t := time.Unix(int64(pl.Expires), 0)
		expiration = t.Format("2006-01-02 03:04:05")
	}

	ocsShare := &OCSShare{
		ShareType:            ShareTypePublicLink,
		ID:                   pl.Id,
		Token:                pl.Token,
		DisplayNameFileOwner: owner,
		DisplayNameOwner:     owner,
		FileSource:           pl.Path,
		FileTarget:           pl.Path,
		ItemSource:           pl.Path,
		ItemType:             itemType,
		MimeType:             mimeType,
		Name:                 pl.Token,
		Path:                 md.Path,
		Permissions:          permissions,
		ShareTime:            int(pl.Mtime),
		State:                ShareStateAccepted,
		UIDFileOwner:         owner,
		UIDOwner:             owner,
		ShareWith:            shareWith,
		ShareWithDisplayName: shareWith,
		Expiration:           expiration,
	}
	return ocsShare, nil
}

func (p *proxy) getReceivedShares(w http.ResponseWriter, r *http.Request, path string) {
	shares := []*OCSShare{}
	if path == "" {
		shares = []*OCSShare{
			&OCSShare{
				ID:               "244",
				Path:             "/A new Vespa.pdf",
				Permissions:      PermissionRead,
				MimeType:         "application/pdf",
				ShareType:        ShareTypeUser,
				DisplayNameOwner: "Labrador",
				UIDOwner:         "labradorsvc",
				ItemSource:       "home:1234",
				FileSource:       "home:1234",
				FileTarget:       "/A new Vespa.pdf",
				State:            ShareStateAccepted,
				ItemType:         ItemTypeFile,
			},
			&OCSShare{
				ID:               "245",
				Path:             "/Red trail",
				Permissions:      PermissionRead,
				MimeType:         "application/json",
				ShareType:        ShareTypeGroup,
				DisplayNameOwner: "cernbox-admins",
				UIDOwner:         "lmascett",
				ItemSource:       "home:1235",
				FileSource:       "home:1235",
				FileTarget:       "/Red trail",
				State:            ShareStatePending,
				ItemType:         ItemTypeFolder,
			},
			&OCSShare{
				ID:               "246",
				Path:             "/Bad stuff",
				Permissions:      PermissionRead,
				MimeType:         "httpd/unix-directory",
				ShareType:        ShareTypeGroup,
				DisplayNameOwner: "cernbox-admins",
				UIDOwner:         "lmascett",
				ItemSource:       "home:1236",
				FileSource:       "home:1236",
				FileTarget:       "/Bad stuff",
				State:            ShareStateAccepted,
				ItemType:         ItemTypeFolder,
			},
		}
	}
	meta := &ResponseMeta{Status: "ok", StatusCode: 100}
	payload := &OCSPayload{Meta: meta, Data: shares}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

func (p *proxy) getPublicLink(ctx context.Context, id string) (*api.PublicLink, error) {
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getShareClient().InspectPublicLink(gCtx, &api.ShareIDReq{Id: id})
	if err != nil {
		return nil, err
	}

	if res.Status != api.StatusCode_OK {
		if res.Status == api.StatusCode_PUBLIC_LINK_NOT_FOUND {
			return nil, api.NewError(api.PublicLinkNotFoundErrorCode)
		}
	}
	return res.PublicLink, nil
}

func (p *proxy) getOCSPublicLink(ctx context.Context, id string) (*OCSShare, bool, error) {
	pl, err := p.getPublicLink(ctx, id)
	if err == nil {
		ocsShare, err2 := p.publicLinkToOCSShare(ctx, pl)
		if err2 != nil {
			return nil, false, err2
		}
		return ocsShare, true, nil
	}
	if api.IsErrorCode(err, api.PublicLinkNotFoundErrorCode) {
		return nil, false, nil
	}
	return nil, false, err

}

func (p *proxy) getOCSFolderShare(ctx context.Context, id string) (*OCSShare, bool, error) {
	share, err := p.getFolderShare(ctx, id)
	if err == nil {
		ocsShare, err2 := p.folderShareToOCSShare(ctx, share)
		if err2 != nil {
			return nil, false, err2
		}
		return ocsShare, true, nil
	}
	if api.IsErrorCode(err, api.FolderShareNotFoundErrorCode) {
		return nil, false, nil
	}
	return nil, false, err

}

func (p *proxy) getFolderShare(ctx context.Context, id string) (*api.FolderShare, error) {
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getShareClient().GetFolderShare(gCtx, &api.ShareIDReq{Id: id})
	if err != nil {
		return nil, err
	}

	if res.Status != api.StatusCode_OK {
		if res.Status == api.StatusCode_FOLDER_SHARE_NOT_FOUND {
			return nil, api.NewError(api.FolderShareNotFoundErrorCode)
		}
	}
	return res.FolderShare, nil

}

func (p *proxy) getShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// we don't know based on the shareID if this is a public link or folder share,
	// so we query both backends, and the first that responds we use it
	shareID := mux.Vars(r)["share_id"]

	ocsShare, found, err := p.getOCSPublicLink(ctx, shareID)
	ocsShare2, found2, err2 := p.getOCSFolderShare(ctx, shareID)

	if err != nil || err2 != nil {
		p.logger.Error("", zap.Error(err), zap.Error(err2))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if found {
		ocsShares := []*OCSShare{ocsShare}
		meta := &ResponseMeta{Status: "ok", StatusCode: 200}
		payload := &OCSPayload{Meta: meta, Data: ocsShares}
		ocsRes := &OCSResponse{OCS: payload}
		encoded, err := json.Marshal(ocsRes)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(encoded)
		return

	}

	if found2 {
		ocsShares := []*OCSShare{ocsShare2}
		meta := &ResponseMeta{Status: "ok", StatusCode: 200}
		payload := &OCSPayload{Meta: meta, Data: ocsShares}
		ocsRes := &OCSResponse{OCS: payload}
		encoded, err := json.Marshal(ocsRes)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(encoded)
		return

	}

	p.logger.Warn("share not found", zap.String("shareID", shareID))
	w.WriteHeader(http.StatusNotFound)

}

func (p *proxy) deleteShare(w http.ResponseWriter, r *http.Request) {
	// TODO(labkode): separate methods for folder shares and link shares.
	ctx := r.Context()
	gCtx := GetContextWithAuth(ctx)
	shareID := mux.Vars(r)["share_id"]
	res, err := p.getShareClient().RevokePublicLink(gCtx, &api.ShareIDReq{Id: shareID})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != api.StatusCode_OK {
		p.writeError(res.Status, w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *proxy) isPublicLinkShare(ctx context.Context, shareID string) (bool, error) {
	_, err := p.getPublicLink(ctx, shareID)
	if err != nil {
		if api.IsErrorCode(err, api.PublicLinkNotFoundErrorCode) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *proxy) isFolderShare(ctx context.Context, shareID string) (bool, error) {
	_, err := p.getFolderShare(ctx, shareID)
	if err != nil {
		if api.IsErrorCode(err, api.FolderShareNotFoundErrorCode) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// TODO(labkode): check for updateReadOnly
func (p *proxy) updateFolderShare(shareID string, readOnly bool, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &api.UpdateFolderShareReq{Id: shareID, ReadOnly: readOnly, UpdateReadOnly: true}
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getShareClient().UpdateFolderShare(gCtx, req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != api.StatusCode_OK {
		p.writeError(res.Status, w, r)
		return

	}

	share := res.FolderShare
	ocsShare, err := p.folderShareToOCSShare(ctx, share)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	meta := &ResponseMeta{Status: "ok", StatusCode: 200}
	payload := &OCSPayload{Meta: meta, Data: ocsShare}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

// TODO(labkode): check for updateReadOnly
func (p *proxy) updatePublicLinkShare(shareID string, newShare *NewShareOCSRequest, updateExpiration, updatePassword bool, expiration int64, readOnly bool, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	updateLinkReq := &api.UpdateLinkReq{
		UpdateExpiration: updateExpiration,
		UpdatePassword:   updatePassword,
		UpdateReadOnly:   true,
		ReadOnly:         readOnly,
		Password:         newShare.Password.Value,
		Expiration:       uint64(expiration),
		Id:               shareID,
	}

	gCtx := GetContextWithAuth(ctx)
	publicLinkRes, err := p.getShareClient().UpdatePublicLink(gCtx, updateLinkReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if publicLinkRes.Status != api.StatusCode_OK {
		p.writeError(publicLinkRes.Status, w, r)
		return
	}

	publicLink := publicLinkRes.PublicLink
	ocsShare, err := p.publicLinkToOCSShare(ctx, publicLink)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	meta := &ResponseMeta{Status: "ok", StatusCode: 200}
	payload := &OCSPayload{Meta: meta, Data: ocsShare}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}
func (p *proxy) updateShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	shareID := mux.Vars(r)["share_id"]

	newShare := &NewShareOCSRequest{}
	if r.Header.Get("Content-Type") == "application/json" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = json.Unmarshal(body, newShare)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else { // assume x-www-form-urlencoded
		err := r.ParseForm()
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		shareTypeString := r.Form.Get("shareType")
		shareWith := r.Form.Get("shareWith")
		permissionsString := r.Form.Get("permissions")
		path := r.Form.Get("path")

		var shareType ShareType
		var permissions Permission
		if shareTypeString == "0" {
			shareType = ShareTypeUser
		} else if shareTypeString == "1" {
			shareType = ShareTypeGroup
		}

		perm, err := strconv.ParseInt(permissionsString, 10, 64)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		permissions = Permission(perm)

		newShare.Path = path
		newShare.ShareWith = shareWith
		newShare.ShareType = shareType
		newShare.Permissions = permissions

	}

	updateExpiration := false
	updatePassword := false
	var expiration int64
	if newShare.ExpireDate.Set && newShare.ExpireDate.Value != "" {
		updateExpiration = true
		t, err := time.Parse("02-01-2006", newShare.ExpireDate.Value)
		if err != nil {
			p.logger.Error("expire data format is not valid", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		expiration = t.Unix()
	}

	if newShare.Password.Set {
		updatePassword = true
	}

	var readOnly bool
	if newShare.Permissions == PermissionRead {
		readOnly = true
	}

	found, err := p.isPublicLinkShare(ctx, shareID)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if found {
		p.updatePublicLinkShare(shareID, newShare, updateExpiration, updatePassword, expiration, readOnly, w, r)
		return
	}

	found, err = p.isFolderShare(ctx, shareID)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if found {
		p.updateFolderShare(shareID, readOnly, w, r)
		return
	}

	p.logger.Warn("share id not found on public link and folder share managers", zap.String("shareID", shareID))
	w.WriteHeader(http.StatusNotFound)
}

func (p *proxy) acceptShare(w http.ResponseWriter, r *http.Request) {
}

func (p *proxy) rejectShare(w http.ResponseWriter, r *http.Request) {
}

func (p *proxy) isNotFoundError(err error) bool {
	return api.IsErrorCode(err, api.StorageNotFoundErrorCode)
}

func (p *proxy) writeError(status api.StatusCode, w http.ResponseWriter, r *http.Request) {
	p.logger.Warn("write error", zap.Int("status", int(status)))
	if status == api.StatusCode_STORAGE_NOT_FOUND {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if status == api.StatusCode_STORAGE_PERMISSIONDENIED {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
}

func getUserFromContext(ctx context.Context) (*api.User, error) {
	u, ok := api.ContextGetUser(ctx)
	if !ok {
		return nil, api.NewError(api.ContextUserRequiredError)
	}
	return u, nil
}

func GetContextWithAuth(ctx context.Context) context.Context {
	token, _ := api.ContextGetAccessToken(ctx)
	header := metadata.New(map[string]string{"authorization": "bearer " + token})
	return metadata.NewOutgoingContext(context.Background(), header)
}

func (p *proxy) detectMimeType(isDir bool, pa string) string {
	if isDir {
		return "httpd/unix-directory"
	}
	ext := path.Ext(pa)
	return mime.TypeByExtension(ext)
}

type ShareType int
type Permission int
type ItemType string
type ShareState int

const (
	ShareTypeUser       ShareType = 0
	ShareTypeGroup                = 1
	ShareTypePublicLink           = 3

	PermissionRead      Permission = 1
	PermissionReadWrite Permission = 15

	ItemTypeFile   ItemType = "file"
	ItemTypeFolder ItemType = "folder"

	ShareStateAccepted ShareState = 0
	ShareStatePending             = 1
	ShareStateRejected            = 2
)

type ResponseMeta struct {
	Status       string `json:"status"`
	StatusCode   int    `json:"statuscode"`
	Message      string `json:"message"`
	TotalItems   string `json:"totalitems"`
	ItemsPerPage string `json:"itemsperpage"`
}

type OCSPayload struct {
	Meta *ResponseMeta `json:"meta"`
	Data interface{}   `json:"data"`
}

type OCSResponse struct {
	OCS *OCSPayload `json:"ocs"`
}

type JSONInt struct {
	Value int
	Valid bool
	Set   bool
}

type JSONString struct {
	Value string
	Valid bool
	Set   bool
}

func (i *JSONString) UnmarshalJSON(data []byte) error {
	// If this method was called, the value was set.
	i.Set = true

	if string(data) == "null" {
		// The key was set to null
		i.Valid = false
		return nil
	}

	// The key isn't set to null
	var temp string
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	i.Value = temp
	i.Valid = true
	return nil
}

func (i *JSONInt) UnmarshalJSON(data []byte) error {
	// If this method was called, the value was set.
	i.Set = true

	if string(data) == "null" {
		// The key was set to null
		i.Valid = false
		return nil
	}

	// The key isn't set to null
	var temp int
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	i.Value = temp
	i.Valid = true
	return nil
}

type LDAPAccountType string

var (
	LDAPAccountTypePrimary   LDAPAccountType = "primary"
	LDAPAccountTypeSecondary LDAPAccountType = "secondary"
	LDAPAccountTypeService   LDAPAccountType = "service"
	LDAPAccountTypeEGroup    LDAPAccountType = "egroup"
	LDAPAccountTypeUnixGroup LDAPAccountType = "unixgroup"
	LDAPAccountTypeUndefined LDAPAccountType = "undefined"
)
