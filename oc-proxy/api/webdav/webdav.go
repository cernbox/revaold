package webdav

import (
	"bytes"

	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/reva/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Options struct {
	Logger            *zap.Logger
	TemporaryFolder   string
	ChunksFolder      string
	MaxUploadFileSize uint64
	REVAHostname      string
	REVAPort          int
	Router            *mux.Router
}

func (opt *Options) init() {
	if opt.TemporaryFolder == "" {
		opt.TemporaryFolder = os.TempDir()
	}

	if opt.ChunksFolder == "" {
		opt.ChunksFolder = filepath.Join(opt.TemporaryFolder, "chunks")
	}

}

func New(opt *Options) (http.Handler, error) {
	if opt == nil {
		opt = &Options{}
	}

	opt.init()

	if opt.Router == nil {
		opt.Router = mux.NewRouter()
	}

	if err := os.MkdirAll(opt.TemporaryFolder, 0755); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opt.ChunksFolder, 0755); err != nil {
		return nil, err
	}

	proxy := &proxy{
		maxUploadFileSize: int64(opt.MaxUploadFileSize),
		router:            opt.Router,
		chunksFolder:      opt.ChunksFolder,
		temporaryFolder:   opt.TemporaryFolder,
		revaHost:          fmt.Sprintf("%s:%d", opt.REVAHostname, opt.REVAPort),
		logger:            opt.Logger,
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
	temporaryFolder   string
	chunksFolder      string
	maxUploadFileSize int64
	router            *mux.Router
	authClient        api.AuthClient
	storageClient     api.StorageClient
	revaHost          string
	grpcConn          *grpc.ClientConn
	logger            *zap.Logger
}

func (p *proxy) getAuthClient() api.AuthClient {
	return api.NewAuthClient(p.grpcConn)
}

func (p *proxy) getStorageClient() api.StorageClient {
	return api.NewStorageClient(p.grpcConn)
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
	p.router.HandleFunc("/status.php", p.status).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/cloud/capabilities", p.capabilities).Methods("GET")

	// user prefixed webdav routes
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.get)).Methods("GET")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.put)).Methods("PUT")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.options)).Methods("OPTIONS")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.lock)).Methods("LOCK")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.unlock)).Methods("UNLOCK")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.head)).Methods("HEAD")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.mkcol)).Methods("MKCOL")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.proppatch)).Methods("PROPPATCH")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.propfind)).Methods("PROPFIND")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.delete)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/remote.php/dav/files/{username}/{path:.*}", p.basicAuth(p.move)).Methods("MOVE")

	// user-relative routes
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.get)).Methods("GET")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.put)).Methods("PUT")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.options)).Methods("OPTIONS")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.lock)).Methods("LOCK")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.unlock)).Methods("UNLOCK")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.head)).Methods("HEAD")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.mkcol)).Methods("MKCOL")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.proppatch)).Methods("PROPPATCH")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.propfind)).Methods("PROPFIND")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.delete)).Methods("DELETE")
	p.router.HandleFunc("/cernbox/remote.php/webdav/{path:.*}", p.basicAuth(p.move)).Methods("MOVE")
}

func (p *proxy) status(w http.ResponseWriter, r *http.Request) {
	major := "8"
	minor := "2"
	micro := "1"
	edition := ""

	version := fmt.Sprintf("%s.%s.%s.4", major, minor, micro)
	versionString := fmt.Sprintf("%s.%s.%s", major, minor, micro)

	status := &struct {
		Installed     bool   `json:"installed"`
		Maintenance   bool   `json:"maintenance"`
		Version       string `json:"version"`
		VersionString string `json:"versionstring"`
		Edition       string `json:"edition"`
	}{
		true,
		false,
		version,
		versionString,
		edition,
	}

	statusJSON, err := json.MarshalIndent(status, "", "    ")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(statusJSON)
}

func (p *proxy) capabilities(w http.ResponseWriter, r *http.Request) {
	capabilities := `
	{
	  "ocs": {
	    "data": {
	      "capabilities": {
	        "core": {
	          "pollinterval": 60
	        },
	        "files": {
	          "bigfilechunking": true,
	          "undelete": true,
	          "versioning": true
	        }
	      },
	      "version": {
	        "edition": "",
	        "major": 8,
	        "micro": 1,
	        "minor": 2,
	        "string": "8.2.1"
	      }
	    },
	    "meta": {
	      "message": null,
	      "status": "ok",
	      "statuscode": 100
	    }
	  }
	}`

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(capabilities))
}

func (p *proxy) detectMimeType(pa string) string {
	ext := path.Ext(pa)
	return mime.TypeByExtension(ext)
}

func (p *proxy) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := mux.Vars(r)["path"]

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}

	md := mdRes.Metadata
	if md.IsDir {
		p.logger.Warn("file is a folder")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	stream, err := p.getStorageClient().ReadFile(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", p.detectMimeType(md.Path))
	w.Header().Set("ETag", md.Etag)
	w.Header().Set("OC-FileId", md.Id)
	w.Header().Set("OC-ETag", md.Etag)
	t := time.Unix(int64(md.Mtime), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	if md.Checksum != "" {
		w.Header().Set("OC-Checksum", md.Checksum)
	}

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

func (p *proxy) head(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := mux.Vars(r)["path"]

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}
	md := mdRes.Metadata
	w.Header().Set("Content-Type", p.detectMimeType(md.Path))
	w.Header().Set("ETag", md.Etag)
	w.Header().Set("OC-FileId", md.Id)
	w.Header().Set("OC-ETag", md.Etag)
	t := time.Unix(int64(md.Mtime), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	w.WriteHeader(http.StatusOK)
}

func (p *proxy) options(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := mux.Vars(r)["path"]

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}

	md := mdRes.Metadata
	allow := "OPTIONS, LOCK, GET, HEAD, POST, DELETE, PROPPATCH, COPY,"
	allow += " MOVE, UNLOCK, PROPFIND"
	if !md.IsDir {
		allow += ", PUT"
	}

	w.Header().Set("Allow", allow)
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.WriteHeader(http.StatusOK)
	return
}

func (p *proxy) delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := mux.Vars(r)["path"]

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}
	emptyRes, err := p.getStorageClient().Delete(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *proxy) lock(w http.ResponseWriter, r *http.Request) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
	<prop xmlns="DAV:">
		<lockdiscovery>
			<activelock>
				<allprop/>
				<timeout>Second-604800</timeout>
				<depth>Infinity</depth>
				<locktoken>
				<href>opaquelocktoken:00000000-0000-0000-0000-000000000000</href>
				</locktoken>
			</activelock>
		</lockdiscovery>
	</prop>`

	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	w.Header().Set("Lock-Token",
		"opaquelocktoken:00000000-0000-0000-0000-000000000000")
	w.Write([]byte(xml))
}

func (p *proxy) unlock(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (p *proxy) mkcol(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := mux.Vars(r)["path"]

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}
	emptyRes, err := p.getStorageClient().CreateDir(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (p *proxy) proppatch(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (p *proxy) move(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oldPath := mux.Vars(r)["path"]

	destination := r.Header.Get("Destination")
	overwrite := r.Header.Get("Overwrite")

	if destination == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	destinationURL, err := url.ParseRequestURI(destination)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	overwrite = strings.ToUpper(overwrite)
	if overwrite == "" {
		overwrite = "T"
	}

	if overwrite != "T" && overwrite != "F" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// remove api base and service base to get real path
	//toTrim := filepath.Join("/", dirs.Server.BaseURL, dirs.OCWebDAV.BaseURL) + "/cernbox/remote.php/dav/files/"
	toTrim := "/cernbox/remote.php/dav/files/gonzalhu/"
	destination = path.Join("/", path.Clean(strings.TrimPrefix(destinationURL.Path, toTrim)))

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.MoveReq{OldPath: oldPath, NewPath: destination}
	emptyRes, err := p.getStorageClient().Move(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	gReq2 := &api.PathReq{Path: destination}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq2)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}
	md := mdRes.Metadata

	w.Header().Set("ETag", md.Etag)
	w.Header().Set("OC-FileId", md.Id)
	w.Header().Set("OC-ETag", md.Etag)

	// ownCloud want a 201 instead of 204
	w.WriteHeader(http.StatusCreated)
}

func (p *proxy) put(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		p.logger.Error("body is <nil>")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	path := mux.Vars(r)["path"]

	// if request is a chunk upload we handle it in another method
	isChunked, err := p.isChunkedUpload(path)
	if err != nil {
		p.logger.Error("error applying chunk regex to path", zap.String("path", path))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if isChunked {
		p.logger.Info("upload is chunked")
		p.putChunked(w, r)
		return
	}

	if p.requestHasContentRange(r) {
		p.logger.Warn("content-range header is not accepted on put requests")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	if p.requestSuffersFinderProblem(r) {
		if err := p.handleFinderRequest(w, r); err != nil {
			return
		}
	}

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		if mdRes.Status != api.StatusCode_STORAGE_NOT_FOUND {
			p.writeError(mdRes.Status, w, r)
			return
		}

	}
	md := mdRes.Metadata

	if md != nil && md.IsDir {
		p.logger.Warn("file already exists and is a folder", zap.String("path", md.Path))
		w.WriteHeader(http.StatusConflict)
		return
	}

	// if If-Match header contains an Etag we need to check it against the ETag from the server
	// so see if they match or not. If they do not match, StatusPreconditionFailed is returned
	if md != nil {
		clientETag := r.Header.Get("If-Match")
		serverETag := md.Etag
		if clientETag != "" {
			if err := p.handleIfMatchHeader(clientETag, serverETag, w, r); err != nil {
				p.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusPreconditionRequired)
				return
			}
		}
	}

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

	buffer := make([]byte, 1024*1024*3)
	offset := uint64(0)
	numChunks := uint64(0)

	readCloser := http.MaxBytesReader(w, r.Body, p.maxUploadFileSize)
	defer readCloser.Close()

	for {
		n, err := readCloser.Read(buffer)
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

	modifiedMdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if modifiedMdRes.Status != api.StatusCode_OK {
		p.writeError(modifiedMdRes.Status, w, r)
		return
	}
	modifiedMd := modifiedMdRes.Metadata

	w.Header().Add("Content-Type", p.detectMimeType(modifiedMd.Path))
	w.Header().Set("ETag", modifiedMd.Etag)
	w.Header().Set("OC-FileId", modifiedMd.Id)
	w.Header().Set("OC-ETag", modifiedMd.Etag)
	t := time.Unix(int64(modifiedMd.Mtime), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	w.Header().Set("X-OC-MTime", "accepted")

	// if object did not exist, http code is 201, else 204.
	if md == nil {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	return

}

func (p *proxy) createChunkTempFile() (string, *os.File, error) {
	file, err := ioutil.TempFile(fmt.Sprintf("/%s", p.chunksFolder), "")
	if err != nil {
		return "", nil, err
	}

	return file.Name(), file, nil
}

func (p *proxy) getChunkFolderName(i *chunkBLOBInfo) (string, error) {
	path := "/" + p.chunksFolder + filepath.Clean("/"+i.uploadID())
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	return path, nil
}

func (p *proxy) saveChunk(ctx context.Context, path string, r io.ReadCloser) (bool, string, error) {
	chunkInfo, err := getChunkBLOBInfo(path)
	if err != nil {
		err := fmt.Errorf("error getting chunk info from path: %s", path)
		//c.logger.Error().Log("error", err)
		return false, "", err
	}

	//c.logger.Info().Log("chunknum", chunkInfo.currentChunk, "chunks", chunkInfo.totalChunks,
	//"transferid", chunkInfo.transferID, "uploadid", chunkInfo.uploadID())

	chunkTempFilename, chunkTempFile, err := p.createChunkTempFile()
	if err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}
	defer chunkTempFile.Close()

	if _, err := io.Copy(chunkTempFile, r); err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}

	// force close of the file here because if it is the last chunk to
	// assemble the big file we must have all the chunks already closed.
	if err = chunkTempFile.Close(); err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}

	chunksFolderName, err := p.getChunkFolderName(chunkInfo)
	if err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}
	//c.logger.Info().Log("chunkfolder", chunksFolderName)

	chunkTarget := chunksFolderName + "/" + fmt.Sprintf("%d", chunkInfo.currentChunk)
	if err = os.Rename(chunkTempFilename, chunkTarget); err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}

	//c.logger.Info().Log("chunktarget", chunkTarget)

	// Check that all chunks are uploaded.
	// This is very inefficient, the server has to check that it has all the
	// chunks after each uploaded chunk.
	// A two-phase upload like DropBox is better, because the server will
	// assembly the chunks when the client asks for it.
	chunksFolder, err := os.Open(chunksFolderName)
	if err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}
	defer chunksFolder.Close()

	// read all the chunks inside the chunk folder; -1 == all
	chunks, err := chunksFolder.Readdir(-1)
	if err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}
	//c.logger.Info().Log("msg", "chunkfolder readed", "nchunks", len(chunks))

	// there is still some chunks to be uploaded.
	// we return CodeUploadIsPartial to notify uper layers that the upload is still
	// not complete and requires more actions.
	// This code is needed to notify the owncloud webservice that the upload has not yet been
	// completed and needs to continue uploading chunks.
	if len(chunks) < int(chunkInfo.totalChunks) {
		return false, "", nil
	}

	assembledFileName, assembledFile, err := p.createChunkTempFile()
	if err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}
	defer assembledFile.Close()

	//c.logger.Info().Log("assembledfile", assembledFileName)

	// walk all chunks and append to assembled file
	for i := range chunks {
		target := chunksFolderName + "/" + fmt.Sprintf("%d", i)

		chunk, err := os.Open(target)
		if err != nil {
			//c.logger.Error().Log("error", err)
			return false, "", err
		}
		defer chunk.Close()

		if _, err = io.Copy(assembledFile, chunk); err != nil {
			//c.logger.Error().Log("error", err)
			return false, "", err
		}
		//c.logger.Debug().Log("msg", "chunk appended to assembledfile")

		// we close the chunk here because if the assembled file contains hundreds of chunks
		// we will end up with hundreds of open file descriptors
		if err = chunk.Close(); err != nil {
			//c.logger.Error().Log("error", err)
			return false, "", err

		}
	}

	// at this point the assembled file is complete
	// so we free space removing the chunks folder
	defer func() {
		if err = os.RemoveAll(chunksFolderName); err != nil {
			//c.logger.Crit().Log("error", err, "msg", "error deleting chunk folder")
		}
	}()

	// when writing to the assembled file the write pointer points to the end of the file
	// so we need to seek it to the beginning
	if _, err = assembledFile.Seek(0, 0); err != nil {
		//c.logger.Error().Log("error", err)
		return false, "", err
	}

	tempFileName := assembledFileName
	return true, tempFileName, nil
}

func (p *proxy) putChunked(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	path := mux.Vars(r)["path"]
	readCloser := http.MaxBytesReader(w, r.Body, p.maxUploadFileSize)
	finish, fn, err := p.saveChunk(ctx, path, readCloser)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !finish {
		w.WriteHeader(http.StatusPartialContent)
		return
	}

	fd, err := os.Open(fn)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer fd.Close()

	chunkInfo, _ := getChunkBLOBInfo(path)
	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: chunkInfo.path}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	// if err is not found it is okay to continue
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		if mdRes.Status != api.StatusCode_STORAGE_NOT_FOUND {
			p.writeError(mdRes.Status, w, r)
			return
		}
	}

	md := mdRes.Metadata
	if md != nil && md.IsDir {
		p.logger.Warn("file already exists and is a folder", zap.String("path", md.Path))
		w.WriteHeader(http.StatusConflict)
		return
	}

	// if If-Match header contains an Etag we need to check it against the ETag from the server
	// so see if they match or not. If they do not match, StatusPreconditionFailed is returned
	if md != nil {
		clientETag := r.Header.Get("If-Match")
		serverETag := md.Etag
		if clientETag != "" {
			if err := p.handleIfMatchHeader(clientETag, serverETag, w, r); err != nil {
				return
			}
		}
	}

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

	buffer := make([]byte, 1024*1024*3)
	offset := uint64(0)
	numChunks := uint64(0)

	for {
		n, err := fd.Read(buffer)
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
	emptyRes, err := p.getStorageClient().FinishWriteTx(gCtx, &api.TxEnd{Path: chunkInfo.path, TxId: txInfo.TxId})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	modifiedMdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if modifiedMdRes.Status != api.StatusCode_OK {
		p.writeError(modifiedMdRes.Status, w, r)
		return
	}

	modifiedMd := modifiedMdRes.Metadata
	w.Header().Add("Content-Type", p.detectMimeType(modifiedMd.Path))
	w.Header().Set("ETag", modifiedMd.Etag)
	w.Header().Set("OC-FileId", modifiedMd.Id)
	w.Header().Set("OC-ETag", modifiedMd.Etag)
	t := time.Unix(int64(modifiedMd.Mtime), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	w.Header().Set("X-OC-MTime", "accepted")

	// if object did not exist, http code is 201, else 204.
	if md == nil {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	return

}
func (p *proxy) propfind(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := mux.Vars(r)["path"]

	gCtx := GetContextWithAuth(ctx)
	gReq := &api.PathReq{Path: path}

	var children bool
	depth := r.Header.Get("Depth")
	// TODO(labkode) Check default for infinity header
	if depth == "1" {
		children = true
	}

	var mds []*api.Metadata
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}
	md := mdRes.Metadata
	mds = append(mds, md)

	if children && md.IsDir {
		stream, err := p.getStorageClient().ListFolder(gCtx, gReq)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		for {
			mdRes, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				p.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if mdRes.Status != api.StatusCode_OK {
				p.writeError(mdRes.Status, w, r)
				return
			}
			md = mdRes.Metadata
			mds = append(mds, md)
		}
	}

	mdsInXML, err := p.mdsToXML(ctx, mds)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("DAV", "1, 3, extended-mkcol")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	w.Write([]byte(mdsInXML))

}

func (p *proxy) isChunkedUpload(path string) (bool, error) {
	return regexp.MatchString(`-chunking-\w+-[0-9]+-[0-9]+$`, path)
}

func (p *proxy) handleIfMatchHeader(clientETag, serverETag string, w http.ResponseWriter, r *http.Request) error {
	// ownCloud adds double quotes around ETag value
	serverETag = fmt.Sprintf(`"%s"`, serverETag)
	if clientETag != serverETag {
		err := fmt.Errorf("etags do not match")
		p.logger.Error("can not accept conditional request", zap.String("client-etag", clientETag), zap.String("server-etag", serverETag))
		w.WriteHeader(http.StatusPreconditionFailed)
		return err
	}

	return nil
}

func (p *proxy) handleFinderRequest(w http.ResponseWriter, r *http.Request) error {
	/*
	   Many webservers will not cooperate well with Finder PUT requests,
	   because it uses 'Chunked' transfer encoding for the request body.
	   The symptom of this problem is that Finder sends files to the
	   server, but they arrive as 0-length files in PHP.
	   If we don't do anything, the user might think they are uploading
	   files successfully, but they end up empty on the server. Instead,
	   we throw back an error if we detect this.
	   The reason Finder uses Chunked, is because it thinks the files
	   might change as it's being uploaded, and therefore the
	   Content-Length can vary.
	   Instead it sends the X-Expected-Entity-Length header with the size
	   of the file at the very start of the request. If this header is set,
	   but we don't get a request body we will fail the request to
	   protect the end-user.
	*/
	p.logger.Warn("finder problem intercepted", zap.String("content-length", r.Header.Get("Content-Length")), zap.String("x-expected-entity-length", r.Header.Get("X-Expected-Entity-Length")))

	// The best mitigation to this problem is to tell users to not use crappy Finder.
	// Another possible mitigation is to change the use the value of X-Expected-Entity-Length header in the Content-Length header.
	expected := r.Header.Get("X-Expected-Entity-Length")
	expectedInt, err := strconv.ParseInt(expected, 10, 64)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	r.ContentLength = expectedInt
	return nil
}

func (p *proxy) requestSuffersFinderProblem(r *http.Request) bool {
	return r.Header.Get("X-Expected-Entity-Length") != ""
}

func (p *proxy) requestHasContentRange(r *http.Request) bool {
	/*
	   Content-Range is dangerous for PUT requests:  PUT per definition
	   stores a full resource.  draft-ietf-httpbis-p2-semantics-15 says
	   in section 7.6:
	     An origin server SHOULD reject any PUT request that contains a
	     Content-Range header field, since it might be misinterpreted as
	     partial content (or might be partial content that is being mistakenly
	     PUT as a full representation).  Partial content updates are possible
	     by targeting a separately identified resource with state that
	     overlaps a portion of the larger resource, or by using a different
	     method that has been specifically defined for partial updates (for
	     example, the PATCH method defined in [RFC5789]).
	   This clarifies RFC2616 section 9.6:
	     The recipient of the entity MUST NOT ignore any Content-*
	     (e.g. Content-Range) headers that it does not understand or implement
	     and MUST return a 501 (Not Implemented) response in such cases.
	   OTOH is a PUT request with a Content-Range currently the only way to
	   continue an aborted upload request and is supported by curl, mod_dav,
	   Tomcat and others.  Since some clients do use this feature which results
	   in unexpected behaviour (cf PEAR::HTTP_WebDAV_Client 1.0.1), we reject
	   all PUT requests with a Content-Range for now.
	*/
	return r.Header.Get("Content-Range") != ""
}

func (p *proxy) isNotFoundError(err error) bool {
	return api.IsErrorCode(err, api.StorageNotFoundErrorCode)
}

type chunkHeaderInfo struct {
	// OC-Chunked = 1
	ochunked bool

	// OC-Chunk-Size
	ocChunkSize uint64

	// OC-Total-Length
	ocTotalLength uint64
}

type chunkBLOBInfo struct {
	path         string
	transferID   string
	totalChunks  int64
	currentChunk int64
}

// not using the resource path in the chunk folder name allows uploading
// to the same folder after a move without having to restart the chunk
// upload
func (c *chunkBLOBInfo) uploadID() string {
	return fmt.Sprintf("chunking-%s-%d", c.transferID, c.totalChunks)
}

func getChunkBLOBInfo(path string) (*chunkBLOBInfo, error) {
	parts := strings.Split(path, "-chunking-")
	tail := strings.Split(parts[1], "-")

	totalChunks, err := strconv.ParseInt(tail[1], 10, 64)
	if err != nil {
		return nil, err
	}

	currentChunk, err := strconv.ParseInt(tail[2], 10, 64)
	if err != nil {
		return nil, err
	}
	if currentChunk >= totalChunks {
		return nil, fmt.Errorf("current chunk:%d exceeds total number of chunks:%d", currentChunk, totalChunks)
	}

	return &chunkBLOBInfo{
		path:         parts[0],
		transferID:   tail[0],
		totalChunks:  totalChunks,
		currentChunk: currentChunk,
	}, nil
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

func (p *proxy) mdsToXML(ctx context.Context, mds []*api.Metadata) (string, error) {
	responses := []*responseXML{}
	for _, md := range mds {
		res, err := p.mdToPropResponse(ctx, md)
		if err != nil {
			return "", err
		}
		responses = append(responses, res)
	}
	responsesXML, err := xml.Marshal(&responses)
	if err != nil {
		return "", err
	}

	msg := `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" `
	msg += `xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns">`
	msg += string(responsesXML) + `</d:multistatus>`
	return msg, nil
}

func (p *proxy) mdToPropResponse(ctx context.Context, md *api.Metadata) (*responseXML, error) {
	propList := []propertyXML{}

	getETag := propertyXML{
		xml.Name{Space: "", Local: "d:getetag"},
		"", []byte(md.Etag)}

	ocPermissions := propertyXML{xml.Name{Space: "", Local: "oc:permissions"},
		"", []byte("RDNVW")}

	quotaUsedBytes := propertyXML{
		xml.Name{Space: "", Local: "d:quota-used-bytes"}, "", []byte("0")}

	quotaAvailableBytes := propertyXML{
		xml.Name{Space: "", Local: "d:quota-available-bytes"}, "",
		[]byte("1000000000")}

	getContentLegnth := propertyXML{
		xml.Name{Space: "", Local: "d:getcontentlength"},
		"", []byte(fmt.Sprintf("%d", md.Size))}

	var getContentType propertyXML
	if md.IsDir {
		getContentType = propertyXML{
			xml.Name{Space: "", Local: "d:getcontenttype"},
			"", []byte("httpd/unix-directory")}

	} else {
		getContentType = propertyXML{
			xml.Name{Space: "", Local: "d:getcontenttype"},
			"", []byte(p.detectMimeType(md.Path))}

	}

	// Finder needs the the getLastModified property to work.
	t := time.Unix(int64(md.Mtime), 0)
	lasModifiedString := t.Format(time.RFC1123)
	getLastModified := propertyXML{
		xml.Name{Space: "", Local: "d:getlastmodified"},
		"", []byte(lasModifiedString)}

	getResourceType := propertyXML{
		xml.Name{Space: "", Local: "d:resourcetype"},
		"", []byte("")}

	if md.IsDir {
		getResourceType.InnerXML = []byte("<d:collection/>")
		getContentType.InnerXML = []byte("httpd/unix-directory")
		ocPermissions.InnerXML = []byte("RDNVCK")
	}

	ocID := propertyXML{xml.Name{Space: "", Local: "oc:fileid"}, "",
		[]byte(md.Id)}

	ocDownloadURL := propertyXML{xml.Name{Space: "", Local: "oc:downloadURL"},
		"", []byte("")}

	ocDC := propertyXML{xml.Name{Space: "", Local: "oc:dDC"},
		"", []byte("")}

	propList = append(propList, getResourceType, getContentLegnth, getContentType, getLastModified, // general WebDAV properties
		getETag, quotaAvailableBytes, quotaUsedBytes, ocID, ocDownloadURL, ocDC, ocPermissions) // properties needed by ownCloud

	// PropStat, only HTTP/1.1 200 is sent.
	propStatList := []propstatXML{}

	propStat := propstatXML{}
	propStat.Prop = propList
	propStat.Status = "HTTP/1.1 200 OK"
	propStatList = append(propStatList, propStat)

	response := responseXML{}

	// TODO(labkode): harden check for user
	user, _ := api.ContextGetUser(ctx)
	response.Href = path.Join("/cernbox/remote.php/dav/files", user.AccountId, md.Path)
	if md.IsDir {
		response.Href = path.Join("/cernbox/remote.php/dav/files", user.AccountId, md.Path) + "/"
	}

	response.Propstat = propStatList

	return &response, nil

}

type responseXML struct {
	XMLName             xml.Name      `xml:"d:response"`
	Href                string        `xml:"d:href"`
	Propstat            []propstatXML `xml:"d:propstat"`
	Status              string        `xml:"d:status,omitempty"`
	Error               *errorXML     `xml:"d:error"`
	ResponseDescription string        `xml:"d:responsedescription,omitempty"`
}

// http://www.ocwebdav.org/specs/rfc4918.html#ELEMENT_propstat
type propstatXML struct {
	// Prop requires DAV: to be the default namespace in the enclosing
	// XML. This is due to the standard encoding/xml package currently
	// not honoring namespace declarations inside a xmltag with a
	// parent element for anonymous slice elements.
	// Use of multistatusWriter takes care of this.
	Prop                []propertyXML `xml:"d:prop>_ignored_"`
	Status              string        `xml:"d:status"`
	Error               *errorXML     `xml:"d:error"`
	ResponseDescription string        `xml:"d:responsedescription,omitempty"`
}

// Property represents a single DAV resource property as defined in RFC 4918.
// http://www.ocwebdav.org/specs/rfc4918.html#data.model.for.resource.properties
type propertyXML struct {
	// XMLName is the fully qualified name that identifies this property.
	XMLName xml.Name

	// Lang is an optional xml:lang attribute.
	Lang string `xml:"xml:lang,attr,omitempty"`

	// InnerXML contains the XML representation of the property value.
	// See http://www.ocwebdav.org/specs/rfc4918.html#property_values
	//
	// Property values of complex type or mixed-content must have fully
	// expanded XML namespaces or be self-contained with according
	// XML namespace declarations. They must not rely on any XML
	// namespace declarations within the scope of the XML document,
	// even including the DAV: namespace.
	InnerXML []byte `xml:",innerxml"`
}

// http://www.ocwebdav.org/specs/rfc4918.html#ELEMENT_error
type errorXML struct {
	XMLName  xml.Name `xml:"d:error"`
	InnerXML []byte   `xml:",innerxml"`
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
