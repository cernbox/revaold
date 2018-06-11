package ocs

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cernbox/reva/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net/http"
	"path"
)

type ShareType int
type Permission int
type ItemType string
type ShareState int

const (
	ShareTypeUser       ShareType = 0
	ShareTypeGroup                = 1
	ShareTypePublicLink           = 2

	PermissionRead  Permission = 1
	PermissionWrite Permission = 15

	ItemTypeFile   ItemType = "file"
	ItemTypeFolder ItemType = "folder"

	ShareStateAccepted ShareState = 0
	ShareStatePending             = 1
	ShareStateRejected            = 2
)

type ResponseMeta struct {
	Status     string `json:"status"`
	StatusCode int    `json:"statuscode"`
	Message    string `json:"message"`
}

type OCSPayload struct {
	Meta *ResponseMeta `json:"meta"`
	Data interface{}   `json:"data"`
}

type OCSResponse struct {
	OCS *OCSPayload `json:"ocs"`
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
}

type Options struct {
	Logger       *zap.Logger
	REVAHostname string
	REVAPort     int
	Router       *mux.Router
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
		router:   opt.Router,
		revaHost: fmt.Sprintf("%s:%d", opt.REVAHostname, opt.REVAPort),
		logger:   opt.Logger,
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
	router     *mux.Router
	authClient api.AuthClient
	revaHost   string
	grpcConn   *grpc.ClientConn
	logger     *zap.Logger
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

func (p *proxy) registerRoutes() {
	// requests targeting a file/folder
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares", p.basicAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")

	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares", p.basicAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")

	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares", p.basicAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/pending/{share_id}", p.basicAuth(p.acceptShare)).Methods("POST")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/pending/{share_id}", p.basicAuth(p.rejectShare)).Methods("DELETE")

	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares", p.basicAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.basicAuth(p.updateShare)).Methods("PUT")
}

func (p *proxy) getShares(w http.ResponseWriter, r *http.Request) {
	sharedWithMe := r.URL.Query().Get("shared_with_me")
	if sharedWithMe == "true" {
		p.getReceivedShares(w, r)
		return
	}
	path := r.URL.Query().Get("path")
	w.Write([]byte(sharedWithMe))
	w.Write([]byte(path))
}

func (p *proxy) getReceivedShares(w http.ResponseWriter, r *http.Request) {
	meta := &ResponseMeta{Status: "ok", StatusCode: 100}
	shares := []*OCSShare{
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

func (p *proxy) getShare(w http.ResponseWriter, r *http.Request) {
	sharedWithMe := r.Header.Get("shared_with_me")
	w.Write([]byte(sharedWithMe))
}
func (p *proxy) deleteShare(w http.ResponseWriter, r *http.Request) {
	sharedWithMe := r.Header.Get("shared_with_me")
	w.Write([]byte(sharedWithMe))
}
func (p *proxy) updateShare(w http.ResponseWriter, r *http.Request) {
	sharedWithMe := r.Header.Get("shared_with_me")
	w.Write([]byte(sharedWithMe))
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
