package api

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"net/url"
	gourl "net/url"
	"os"
	"os/exec"
	gouser "os/user"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	reva_api "github.com/cernbox/revaold/api"

	"github.com/bluele/gcache"
	"github.com/disintegration/imaging"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rwcarlsen/goexif/exif"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var shareIDRegexp = regexp.MustCompile(`\(id:.+\)$`)

func (p *proxy) registerRoutes() {
	p.router.HandleFunc("/status.php", p.status).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/cloud/capabilities", p.capabilities).Methods("GET")
	p.router.HandleFunc("/index.php/ocs/cloud/user", p.tokenAuth(p.getCurrentUser)).Methods("GET")

	// user prefixed webdav routes
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.get)).Methods("GET")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.put)).Methods("PUT")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.options)).Methods("OPTIONS")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.lock)).Methods("LOCK")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.unlock)).Methods("UNLOCK")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.head)).Methods("HEAD")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.mkcol)).Methods("MKCOL")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.proppatch)).Methods("PROPPATCH")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.propfind)).Methods("PROPFIND")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.delete)).Methods("DELETE")
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.move)).Methods("MOVE")

	// user-relative routes
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.get)).Methods("GET")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.put)).Methods("PUT")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.options)).Methods("OPTIONS")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.lock)).Methods("LOCK")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.unlock)).Methods("UNLOCK")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.head)).Methods("HEAD")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.mkcol)).Methods("MKCOL")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.proppatch)).Methods("PROPPATCH")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.propfind)).Methods("PROPFIND")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.delete)).Methods("DELETE")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.move)).Methods("MOVE")

	// favorites routes
	p.router.HandleFunc("/remote.php/dav/files/{username}/{path:.*}", p.tokenAuth(p.getFav)).Methods("REPORT")
	p.router.HandleFunc("/remote.php/webdav{path:.*}", p.tokenAuth(p.getFav)).Methods("REPORT")
	p.router.HandleFunc("/index.php/apps/files/api/v1/files/{path:.*}", p.tokenAuth(p.modifyFav)).Methods("POST")

	// public link webdav access
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.get)).Methods("GET")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.put)).Methods("PUT")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.options)).Methods("OPTIONS")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.lock)).Methods("LOCK")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.unlock)).Methods("UNLOCK")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.head)).Methods("HEAD")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.mkcol)).Methods("MKCOL")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.proppatch)).Methods("PROPPATCH")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.propfind)).Methods("PROPFIND")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.delete)).Methods("DELETE")
	p.router.HandleFunc("/public.php/webdav{path:.*}", p.tokenAuth(p.move)).Methods("MOVE")

	// gallery app routes
	p.router.HandleFunc("/index.php/apps/gallery/config.public", p.getGalleryConfig).Methods("GET")
	p.router.HandleFunc("/index.php/apps/gallery/config", p.getGalleryConfig).Methods("GET")
	p.router.HandleFunc("/index.php/apps/gallery/preview/{path:.*}", p.tokenAuth(p.getGalleryPreview)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/gallery/preview.public/{path:.*}", p.tokenAuth(p.getGalleryPreview)).Methods("GET")

	// requests targeting a file/folder
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares", p.tokenAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares", p.tokenAuth(p.createShare)).Methods("POST")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.tokenAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.tokenAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}", p.tokenAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares", p.tokenAuth(p.getRemoteShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.tokenAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.tokenAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.tokenAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/ocs/v2.php/apps/files_sharing/api/v1/sharees", p.tokenAuth(p.search)).Methods("GET")

	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares", p.tokenAuth(p.getShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares", p.tokenAuth(p.createShare)).Methods("POST")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.tokenAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.tokenAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/{share_id}", p.tokenAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/pending/{share_id}", p.tokenAuth(p.acceptShare)).Methods("POST")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/shares/pending/{share_id}", p.tokenAuth(p.rejectShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares", p.tokenAuth(p.getRemoteShares)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.tokenAuth(p.getShare)).Methods("GET")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.tokenAuth(p.deleteShare)).Methods("DELETE")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/remote_shares/{share_id}", p.tokenAuth(p.updateShare)).Methods("PUT")
	p.router.HandleFunc("/ocs/v1.php/apps/files_sharing/api/v1/sharees", p.tokenAuth(p.search)).Methods("GET")

	// public link routes
	p.router.HandleFunc("/index.php/s/{token}", p.renderPublicLink).Methods("GET", "POST")
	p.router.HandleFunc("/index.php/s/{token}/download", p.publicLinkAuth(p.tokenAuth(p.downloadArchivePL))).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files_sharing/ajax/publicpreview.php", p.tokenAuth(p.getPublicPreview)).Methods("GET")

	// app routes
	p.router.HandleFunc("/index.php/apps/files_texteditor/ajax/loadfile", p.tokenAuth(p.loadFile)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files_texteditor/ajax/savefile", p.tokenAuth(p.saveFile)).Methods("PUT")
	p.router.HandleFunc("/index.php/apps/files/ajax/download.php", p.tokenAuth(p.downloadArchive)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files/ajax/getstoragestats.php", p.tokenAuth(p.getStorageStats)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/eosinfo/getinfo", p.tokenAuth(p.getEOSInfo)).Methods("POST")
	p.router.HandleFunc("/index.php/apps/files_eostrashbin/ajax/list.php", p.tokenAuth(p.listTrashbin)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files_eostrashbin/ajax/undelete.php", p.tokenAuth(p.restoreTrashbin)).Methods("POST")
	p.router.HandleFunc("/index.php/apps/files_eosversions/ajax/getVersions.php", p.tokenAuth(p.getVersions)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files_eosversions/ajax/rollbackVersion.php", p.tokenAuth(p.rollbackVersion)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files_eosversions/download.php", p.tokenAuth(p.downloadVersion)).Methods("GET")

	// avatars
	p.router.HandleFunc("/index.php/avatar/{username}/{size}", p.tokenAuth(p.getAvatar)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/files_sharing/api/externalShares", p.tokenAuth(p.getExternalShares)).Methods("GET")

	// project spaces
	p.router.HandleFunc("/index.php/apps/files_projectspaces/ajax/personal_list.php", p.tokenAuth(p.getPersonalProjects)).Methods("GET")

	// wopi routes
	p.router.HandleFunc("/index.php/apps/wopiviewer/config", p.getWopiConfig).Methods("GET")
	p.router.HandleFunc("/index.php/apps/wopiviewer/open", p.tokenAuth(p.wopiOpen)).Methods("POST")
	p.router.HandleFunc("/index.php/apps/wopiviewer/publicopen", p.tokenAuth(p.wopiPublicOpen)).Methods("POST")

	// swan routes
	p.router.HandleFunc("/index.php/apps/swanviewer/eosinfo", p.tokenAuth(p.swanEosInfo)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/swanviewer/load", p.tokenAuth(p.swanLoad)).Methods("GET")
	p.router.HandleFunc("/index.php/apps/swanviewer/publicload", p.tokenAuth(p.swanPublicLoad)).Methods("GET")

	// drawio routes
	p.router.HandleFunc("/index.php/apps/drawio/ajax/settings", p.drawioSettings).Methods("GET")

	// onlyoffice routes
	p.router.HandleFunc("/index.php/apps/onlyoffice/ajax/settings", p.getOnlyOfficeSettings).Methods("GET")
	//p.router.HandleFunc("/index.php/apps/onlyoffice/{path}", p.).Methods("GET")

	// mailer routes
	p.router.HandleFunc("/index.php/apps/mailer/sendmail", p.tokenAuth(p.sendMail)).Methods("POST")

	// rootviewer routes
	p.router.HandleFunc("/index.php/apps/rootviewer/load", p.tokenAuth(p.loadRootFile))
	p.router.HandleFunc("/index.php/apps/rootviewer/publicload", p.tokenAuth(p.loadPublicRootFile))

}

func (p *proxy) loadPublicRootFile(w http.ResponseWriter, r *http.Request) {
	p.loadRootFile(w, r)
}

func (p *proxy) loadRootFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filename := r.URL.Query().Get("filename")

	revaPath := p.getRevaPath(ctx, filename)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO(labkode): stop loading huge files, set max to 1mib?
	if int(md.Size) > p.viewerMaxFileSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		p.logger.Warn("file is too big to be opened in the browser", zap.Int("max_size", p.viewerMaxFileSize), zap.Int("file_size", int(md.Size)))
		msg := fmt.Sprintf("The file is too big to be opened in the browser (maximum size is %d  bytes)", p.viewerMaxFileSize)
		w.Write([]byte(fmt.Sprintf(`{ "message": "%s" }`, msg)))
		return
	}

	gCtx := GetContextWithAuth(ctx)
	pathReq := &reva_api.PathReq{Path: revaPath}
	stream, err := p.getStorageClient().ReadFile(gCtx, pathReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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
		if dcRes.Status != reva_api.StatusCode_OK {
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

	w.WriteHeader(http.StatusOK)
	w.Write(fileContents)
}

func (p *proxy) sendMail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := r.ParseForm()
	if err != nil {
		err = errors.Wrap(err, "error reading form")
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	recipient := r.Form.Get("recipient")
	shareType := r.Form.Get("shareType")
	shareID := r.Form.Get("id")

	share, err := p.getFolderShare(ctx, shareID)
	if err != nil {
		err = errors.Wrap(err, "error getting folder share")
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	md, err := p.getCachedMetadata(ctx, share.Path)
	if err != nil {
		err = errors.Wrap(err, "error getting md for path: "+share.Path)
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, _ := reva_api.ContextGetUser(ctx)
	//owner := user.AccountId
	ownerDisplayName := user.DisplayName
	basename := path.Base(md.EosFile)
	target := fmt.Sprintf("%s (id:%s)", basename, shareID)
	targetEncoded := url.QueryEscape(target)

	mailBody := ""
	if shareType == "0" { // user
		mailBody = "To: %s@cern.ch\r\n" +
			"Subject: %s shared folder '%s' with you\r\n" +
			"\r\n" +
			"%s shared the folder '%s' with you (%s).\r\n\r\n" +
			"If you are logged in as %s you can go to https://cernbox.cern.ch and click the tab 'Shared with you' to find the shared folder called '%s'.\r\n" +
			"You can also access the share directly clicking on this link: https://cernbox.cern.ch/index.php/apps/files/?dir=/__myshares/%s \r\n\r\n" +
			"If you want to sync the share in your desktop, follow this FAQ ( https://cern.service-now.com/service-portal/article.do?n=KB0003663 ) to add a new folder with this path:\r\n\r\n" +
			"%s\r\n" +
			"\r\n" +
			"Best regards,\r\n" +
			"CERNBox Team"

		mailBody = fmt.Sprintf(mailBody, recipient, ownerDisplayName, basename, ownerDisplayName, basename, recipient, recipient, target, targetEncoded, md.EosFile)
	} else {
		mailBody = "To: %s@cern.ch\r\n" +
			"Subject: %s shared folder '%s' with you\r\n" +
			"\r\n" +
			"%s shared the folder '%s' with the e-group '%s' that you are part of it.\r\n\r\n" +
			"If you go to https://cernbox.cern.ch and click the tab 'Shared with you' you will find the shared folder called '%s'.\r\n" +
			"You can also access the share directly clicking on this link: https://cernbox.cern.ch/index.php/apps/files/?dir=/__myshares/%s \r\n\r\n" +
			"If you want to sync the share in your desktop, follow this FAQ ( https://cern.service-now.com/service-portal/article.do?n=KB0003663 ) to add a new folder with this path:\r\n\r\n" +
			"%s\r\n" +
			"\r\n" +
			"Best regards,\r\n" +
			"CERNBox Team"
		mailBody = fmt.Sprintf(mailBody, recipient, ownerDisplayName, basename, ownerDisplayName, basename, recipient, target, targetEncoded, md.EosFile)

	}

	to := []string{recipient + "@cern.ch"}
	err = smtp.SendMail(p.mailServer, nil, p.mailServerFromAddress, to, []byte(mailBody))
	var msg string
	if err != nil {
		err = errors.Wrap(err, "error sending mail")
		p.logger.Error("", zap.Error(err))
		msg = fmt.Sprintf("Error sending mail to: %s@cern.ch", recipient)
		return
	} else {
		msg = fmt.Sprintf("Mail sent to: %s@cern.ch", recipient)
	}

	payload := struct {
		Message string `json:"message"`
	}{msg}
	encoded, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func (p *proxy) getOnlyOfficeSettings(w http.ResponseWriter, r *http.Request) {
	settings := `
{
   "formats":{
      "docx":{
         "mime":"application\/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "type":"text",
         "edit":true,
         "def":true
      },
      "xlsx":{
         "mime":"application\/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         "type":"spreadsheet",
         "edit":true,
         "def":true
      },
      "pptx":{
         "mime":"application\/vnd.openxmlformats-officedocument.presentationml.presentation",
         "type":"presentation",
         "edit":true,
         "def":true
      },
      "ppsx":{
         "mime":"application\/vnd.openxmlformats-officedocument.presentationml.slideshow",
         "type":"presentation",
         "edit":true,
         "def":true
      },
      "txt":{
         "mime":"text\/plain",
         "type":"text",
         "edit":true,
         "def":false
      },
      "csv":{
         "mime":"text\/csv",
         "type":"spreadsheet",
         "edit":true,
         "def":false
      },
      "odt":{
         "mime":"application\/vnd.oasis.opendocument.text",
         "type":"text",
         "conv":true
      },
      "ods":{
         "mime":"application\/vnd.oasis.opendocument.spreadsheet",
         "type":"spreadsheet",
         "conv":true
      },
      "odp":{
         "mime":"application\/vnd.oasis.opendocument.presentation",
         "type":"presentation",
         "conv":true
      },
      "doc":{
         "mime":"application\/msword",
         "type":"text",
         "conv":true
      },
      "xls":{
         "mime":"application\/vnd.ms-excel",
         "type":"spreadsheet",
         "conv":true
      },
      "ppt":{
         "mime":"application\/vnd.ms-powerpoint",
         "type":"presentation",
         "conv":true
      },
      "pps":{
         "mime":"application\/vnd.ms-powerpoint",
         "type":"presentation",
         "conv":true
      },
      "epub":{
         "mime":"application\/epub+zip",
         "type":"text",
         "conv":true
      },
      "rtf":{
         "mime":"text\/rtf",
         "type":"text",
         "conv":true
      },
      "mht":{
         "mime":"message\/rfc822",
         "conv":true
      },
      "html":{
         "mime":"text\/html",
         "type":"text",
         "conv":true
      },
      "htm":{
         "mime":"text\/html",
         "type":"text",
         "conv":true
      },
      "xps":{
         "mime":"application\/vnd.ms-xpsdocument",
         "type":"text"
      },
      "pdf":{
         "mime":"application\/pdf",
         "type":"text"
      },
      "djvu":{
         "mime":"image\/vnd.djvu",
         "type":"text"
      }
   },
   "sameTab":true
}
`

	w.Write([]byte(settings))
}
func (p *proxy) isSyncClient(r *http.Request) bool {
	agent := strings.ToLower(r.UserAgent())
	if strings.Contains(agent, "mirall") {
		return true
	}
	return false
}

// stripCBOXMappedPath returns the the path in the ownCloud namespace.
// For example, the sync client will send /home/Photos and the ocPath will be /Photos.
func (p *proxy) stripCBOXMappedPath(r *http.Request, reqPath string) (string, context.Context) {
	// we need to guess if the request is comming from a sync client or not.
	// the best heuristic we have is to rely on the user-agent.
	ctx := r.Context()

	// TODO(labkode): remove this hack
	if !p.isSyncClient(r) {
		p.logger.Debug("request is not from a sync client")
		return reqPath, ctx
	}

	homePrefix := "/home"
	var ocPath string
	if reqPath != "" {
		ocPath = path.Join("/", strings.TrimPrefix(reqPath, homePrefix))
	}

	ctx = context.WithValue(ctx, "sync-client-ocs-prefix", homePrefix)
	return ocPath, ctx
}

func (p *proxy) joinCBOXMappedPath(ctx context.Context, ocPath string) string {
	val := ctx.Value("sync-client-ocs-prefix")
	if val != nil {
		prefix, ok := val.(string)
		if ok {
			newPath := path.Join(prefix, ocPath)
			return newPath
		}
	}
	return ocPath
}

/*
{
   "formats":{
      "xml":{
         "mime":"application\/xml",
         "type":"text"
      },
      "drawio":{
         "mime":"application\/x-drawio",
         "type":"text"
      }
   },
   "settings":{
      "overrideXml":"yes",
      "offlineMode":"no"
   }
}
*/

func (p *proxy) drawioSettings(w http.ResponseWriter, r *http.Request) {
	payload := fmt.Sprintf(`
	{
	   "formats":{
	      "drawio":{
		 "mime":"application\/x-drawio",
		 "type":"text"
	      }
	   },
	   "settings":{
	      "overrideXml":"no",
	      "offlineMode":"yes"
	   },
	   "urls":{
	      "originUrl":"%s",
	      "drawioUrl":"%s?embed=1&ui=kennedy&lang=en_GB&spin=1&proto=json"
	   }
	}`, p.drawIOURL, p.drawIOURL)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
}

func (p *proxy) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, err := getUserFromContext(ctx)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting user from ctx", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	type response struct {
		Data       interface{} `json:"data"`
		Status     string      `json:"status"`
		StatusCode int         `json:"statuscode"`
	}

	userData := struct {
		ID          string `json:"id"`
		DisplayName string `json:"display-name"`
		Email       string `json:"email"`
	}{ID: user.AccountId, DisplayName: user.AccountId, Email: user.AccountId + "@cern.ch"}

	meta := &ResponseMeta{Status: "ok", StatusCode: 100, Message: "OK"}
	payload := &OCSPayload{Meta: meta, Data: userData}
	res := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(res)
	if err != nil {
		p.logger.Error("ocproxy: api: error in json marshal", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func (p *proxy) swanPublicLoad(w http.ResponseWriter, r *http.Request) {
	p.swanLoad(w, r)
}

func (p *proxy) swanLoad(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filename := r.URL.Query().Get("filename")
	revaPath := p.getRevaPath(ctx, filename)

	gCtx := GetContextWithAuth(ctx)
	pathReq := &reva_api.PathReq{Path: revaPath}
	stream, err := p.getStorageClient().ReadFile(gCtx, pathReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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
		if dcRes.Status != reva_api.StatusCode_OK {
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

	notebook, err := ioutil.TempFile(p.temporaryFolder, "notebook")
	if err != nil {
		p.logger.Error("ocproxy: api: swanLoad: error creating tmp file to store the notebook", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err = notebook.Write(fileContents); err != nil {
		p.logger.Error("ocproxy: api: swanLoad: error writing to tmp file", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	script, err := p.swanGetPythonScript(ctx)
	if err != nil {
		p.logger.Error("ocproxy: api: swanLoad: error ensuring the python script")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	htmlFile := path.Join(p.temporaryFolder, path.Base(notebook.Name()+".html"))

	// convert notebook to html
	cmd := exec.Command("/usr/bin/python3", script, notebook.Name(), htmlFile)
	_, stdErr, exitCode := execute(cmd)
	if exitCode != 0 {
		p.logger.Error("ocproxy: api: swanLoad: error running nbconvert", zap.Int("exitcode", exitCode), zap.String("stderr", stdErr))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	htmlOutput, err := ioutil.ReadFile(htmlFile)
	if err != nil {
		p.logger.Error("ocproxy: api: swanLoad: error reading html output file", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(htmlOutput)
}

func (p *proxy) swanGetPythonScript(ctx context.Context) (string, error) {
	fd, err := ioutil.TempFile(p.temporaryFolder, "notebook-script")
	if err != nil {
		return "", err
	}
	defer fd.Close()

	if _, err = fd.Write([]byte(notebookScript)); err != nil {
		return "", err
	}
	return fd.Name(), nil
}

func (p *proxy) swanEosInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fn := r.URL.Query().Get("filename")
	revaPath := p.getRevaPath(ctx, fn)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting md for swan", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data := struct {
		EosInfo struct {
			EosFile string `json:"eos.file"`
		} `json:"eosinfo"`
	}{struct {
		EosFile string `json:"eos.file"`
	}{md.EosFile}}

	encoded, err := json.Marshal(data)
	if err != nil {
		p.logger.Error("ocproxy: api: swanEosInfo: error encoding to json", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func (p *proxy) wopiPublicOpen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := r.ParseForm()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fn := r.Form.Get("filename")
	token := r.Form.Get("token")
	folderURL := r.Form.Get("folderurl")

	pl, ok := reva_api.ContextGetPublicLink(ctx)
	if !ok {
		p.logger.Warn("ocproxy: api: cannot get public link from ctx")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if pl.Token != token {
		p.logger.Warn("ocproxy: api: pl ctx does not match requested token", zap.String("req_token", token), zap.String("ctx_token", pl.Token))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	revaPath := p.getRevaPath(ctx, fn)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting md for pl", zap.String("reva_path", revaPath), zap.String("token", pl.Token), zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	unixUser, err := gouser.Lookup(pl.OwnerId)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting unix uid/gid", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	uid, gid := unixUser.Uid, unixUser.Gid

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/cbox/open", p.wopiServer)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// wopi accepts booleans as strings :(
	var canEdit string = "false"
	if !pl.ReadOnly {
		canEdit = "true"
	}

	q := req.URL.Query()
	q.Add("ruid", uid)
	q.Add("rgid", gid)
	q.Add("filename", md.EosFile)
	q.Add("canedit", canEdit)
	q.Add("folderurl", folderURL)
	q.Add("username", "")
	q.Add("endpoint", md.EosInstance)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", p.wopiSecret))
	res, err := client.Do(req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.StatusCode != http.StatusOK {
		p.logger.Error("error calling wopi at /cbox/endpoints", zap.Int("status", res.StatusCode))
		w.WriteHeader(res.StatusCode)
		return

	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		p.logger.Error("ocproxy: api: error reading res body on /cbox/open", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	wopiSRC, _ := gourl.QueryUnescape(string(body))
	data := struct {
		WopiSRC string `json:"wopi_src"`
	}{wopiSRC}
	encoded, err := json.Marshal(data)
	if err != nil {
		p.logger.Error("ocproxy: api: error encoding to json", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(encoded)
}

func (p *proxy) wopiOpen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := r.ParseForm()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fn := r.Form.Get("filename")
	folderURL := r.Form.Get("folderurl")
	user, err := getUserFromContext(ctx)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting user from ctx", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	unixUser, err := gouser.Lookup(user.AccountId)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting unix uid/gid", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	uid, gid := unixUser.Uid, unixUser.Gid

	revaPath := p.getRevaPath(ctx, fn)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("ocproxy: api: error getting md", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/cbox/open", p.wopiServer)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// wopi accepts booleans as strings :(
	var canEdit string = "false"
	if !md.IsReadOnly {
		canEdit = "true"
	}

	q := req.URL.Query()
	q.Add("ruid", uid)
	q.Add("rgid", gid)
	q.Add("filename", md.EosFile)
	q.Add("canedit", canEdit)
	q.Add("folderurl", folderURL)
	q.Add("username", user.AccountId)
	q.Add("endpoint", md.EosInstance)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", p.wopiSecret))
	res, err := client.Do(req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.StatusCode != http.StatusOK {
		p.logger.Error("error calling wopi at /cbox/endpoints", zap.Int("status", res.StatusCode))
		w.WriteHeader(res.StatusCode)
		return

	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		p.logger.Error("ocproxy: api: error reading res body on /cbox/open", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	wopiSRC, _ := gourl.QueryUnescape(string(body))
	data := struct {
		WopiSRC string `json:"wopi_src"`
	}{wopiSRC}
	encoded, err := json.Marshal(data)
	if err != nil {
		p.logger.Error("ocproxy: api: error encoding to json", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(encoded)
}

func (p *proxy) getWopiConfig(w http.ResponseWriter, r *http.Request) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/cbox/endpoints", p.wopiServer)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.wopiSecret))
	res, err := client.Do(req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.StatusCode != http.StatusOK {
		p.logger.Error("error calling wopi at /cbox/endpoints", zap.Int("status", res.StatusCode))
		w.WriteHeader(res.StatusCode)
		return

	}
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, res.Body)
}

func (p *proxy) listFolder(ctx context.Context, revaPath string) ([]*reva_api.Metadata, error) {
	gCtx := GetContextWithAuth(ctx)
	gReq := &reva_api.PathReq{Path: revaPath}
	stream, err := p.getStorageClient().ListFolder(gCtx, gReq)
	if err != nil {
		return nil, err
	}

	mds := []*reva_api.Metadata{}
	for {
		mdRes, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if mdRes.Status != reva_api.StatusCode_OK {
			return nil, reva_api.NewError(reva_api.UnknownError)
		}
		md := mdRes.Metadata
		md.Path = p.getOCPath(ctx, md)
		mds = append(mds, md)
	}
	return mds, nil
}

/*
{
   "data":{
      "directory":"\/",
      "files":[
         {
            "fileid":28159344,
            "mtime":1510656728,
            "size":"753647901797",
            "storage_mtime":1510656728,
            "path":"",
            "path_hash":"8f7ff74eee5bdf3c31fd480311dde3fb",
            "parent":12343478,
            "encrypted":0,
            "unencrypted_size":0,
            "name":"  project castor",
            "mimetype":"httpd\/unix-directory",
            "permissions":31,
            "project_owner":"castorc3",
            "project_name":"castor",
            "project_readers":"cernbox-project-castor-readers",
            "project_writers":"cernbox-project-castor-writers",
            "project_admins":"cernbox-project-castor-admins",
            "custom_perm":1,
            "isPreviewAvailable":false,
            "type":"dir"
         },
      ],
      "permissions":1
   },
   "status":"success"
}
*/
type personalProjectsRes struct {
	Data   interface{} `json:"data"`
	Status string      `json:"status"`
}
type personalProjectsData struct {
	Directory   string          `json:"directory"`
	Permissions int             `json:"permissions"`
	Files       []*fileResponse `json:"files"`
}
type fileResponse struct {
	Type        string `json:"type"`
	CustomPerm  int    `json:"custom_perm"`
	FileID      string `json:"fileid"`
	Mtime       uint64 `json:"mtime"`
	Size        uint64 `json:"size"`
	Name        string `json:"name"`
	MimeType    string `json:"mimetype"`
	Permissions int    `json:"permissions"`
	Path        string `json:"path"`
}

func (p *proxy) mdsToPersonalProjectsRes(ctx context.Context, mds []*reva_api.Metadata) *personalProjectsRes {
	files := []*fileResponse{}
	for _, md := range mds {
		file := &fileResponse{FileID: md.Id, Mtime: md.Mtime, Size: md.Size, Name: path.Base(md.Path), MimeType: md.Mime, Permissions: 1, Path: path.Dir(md.Path), Type: "dir", CustomPerm: 1}
		files = append(files, file)
	}
	data := &personalProjectsData{Directory: "/", Permissions: 1, Files: files}
	res := &personalProjectsRes{Data: data, Status: "success"}
	return res
}
func (p *proxy) getPersonalProjects(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := p.ownCloudPersonalProjectsPrefix
	revaPath := p.getRevaPath(ctx, path)
	mds, err := p.listFolder(ctx, revaPath)
	if err != nil {
		p.logger.Error("error listing folder", zap.String("path", path), zap.String("reva_path", revaPath), zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	projects := p.mdsToPersonalProjectsRes(ctx, mds)
	data, err := json.Marshal(projects)
	if err != nil {
		p.logger.Error("ocproxy: api: error json marshaling personal projects response", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (p *proxy) modifyFav(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		p.logger.Error("error reading r.Body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	path := mux.Vars(r)["path"]
	favSet, err := p.isFavSet(ctx, body)
	if err != nil {
		p.logger.Error("cannot infer is operation was to add or remove fav", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if favSet {
		if err := p.setTag(ctx, "fav", path); err != nil {
			p.logger.Error("error setting tag for path", zap.String("path", path), zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// write back body req as reponse
		w.Write(body)
		return
	}

	// operation is to remove the tag
	if err := p.unSetTag(ctx, "fav", path); err != nil {
		p.logger.Error("error unsetting tag for path", zap.String("path", path), zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// write back body req as reponse
	w.Write(body)
}

type setTagReq struct {
	Tags []string `json:"tags"`
}

func (p *proxy) isFavSet(ctx context.Context, body []byte) (bool, error) {
	s := &setTagReq{}
	if err := json.Unmarshal(body, s); err != nil {
		return false, err
	}
	return len(s.Tags) > 0, nil
}

func (p *proxy) setTag(ctx context.Context, key, path string) error {
	revaPath := p.getRevaPath(ctx, path)
	req := &reva_api.TagReq{TagKey: key, Path: revaPath}
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getTagClient().SetTag(gCtx, req)
	if err != nil {
		return err
	}
	if res.Status != reva_api.StatusCode_OK {
		return reva_api.NewError(reva_api.UnknownError)
	}
	return nil
}

func (p *proxy) unSetTag(ctx context.Context, key, path string) error {
	revaPath := p.getRevaPath(ctx, path)
	req := &reva_api.TagReq{TagKey: key, Path: revaPath}
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getTagClient().UnSetTag(gCtx, req)
	if err != nil {
		return err
	}
	if res.Status != reva_api.StatusCode_OK {
		return reva_api.NewError(reva_api.UnknownError)
	}
	return nil
}

func (p *proxy) getTagsForKey(ctx context.Context, key string) ([]*reva_api.Tag, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getTagClient().GetTags(gCtx, &reva_api.TagReq{TagKey: "fav"})
	if err != nil {
		return nil, err
	}

	tags := []*reva_api.Tag{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}
		if res.Status != reva_api.StatusCode_OK {
			return nil, reva_api.NewError(reva_api.UnknownError)
		}
		tags = append(tags, res.Tag)
	}
	return tags, nil
}

func (p *proxy) getFav(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// request comes from remote.php/dav/files/gonzalhu/...
	if mux.Vars(r)["username"] != "" {
		ctx = context.WithValue(ctx, "user-dav-uri", true)
	}

	favs, err := p.getTagsForKey(ctx, "fav")
	if err != nil {
		p.logger.Error("error getting favs", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	mds := p.favsToMD(ctx, favs)
	xmlFavs, err := p.favMDToXML(ctx, mds)
	if err != nil {
		p.logger.Error("error converting fav map to xml", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusMultiStatus)
	w.Write(xmlFavs)
}

func (p *proxy) favsToMD(ctx context.Context, tags []*reva_api.Tag) []*reva_api.Metadata {
	mds := []*reva_api.Metadata{}
	for _, tag := range tags {
		fileid := tag.FileIdPrefix + ":" + tag.FileId
		md, err := p.getMetadata(ctx, fileid)
		if err != nil {
			// TODO(labkode): mark non accessible tags as orphans
			p.logger.Warn("fav is not accessible", zap.Error(err))
			continue
		}
		mds = append(mds, md)
	}

	return mds
}

func (p *proxy) favMDToXML(ctx context.Context, mds []*reva_api.Metadata) ([]byte, error) {
	responses := []*responseXML{}

	for _, md := range mds {
		favProp := p.getFavXMLProp()
		res, err := p.mdToPropResponse(ctx, md, favProp)
		if err != nil {
			p.logger.Error("error converting tag md to xml", zap.Error(err))
			continue
		}
		responses = append(responses, res)
	}

	responsesXML, err := xml.Marshal(&responses)
	if err != nil {
		return nil, err
	}

	msg := `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" `
	msg += `xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns">`
	msg += string(responsesXML) + `</d:multistatus>`
	return []byte(msg), nil
}

func (p *proxy) getFavXMLProp() propertyXML {
	prop := propertyXML{
		xml.Name{Space: "", Local: "oc:favorite"},
		"", []byte("1")}
	return prop
}

func (p *proxy) getExternalShares(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("[]"))

}

func (p *proxy) getAvatar(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"data":{"displayname":"%s"}`, username)))

}

func (p *proxy) getGalleryConfig(w http.ResponseWriter, r *http.Request) {
	msg := ` {"features":[],"mediatypes":["image\/png","image\/jpeg"]}`
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(msg))
}

/*
{
  "data": {
    "uploadMaxFilesize": 2097152,
    "maxHumanFilesize": "Upload (max. 2 MB)",
    "freeSpace": 995088180464,
    "usedSpacePercent": 0,
    "owner": "gonzalhu",
    "ownerDisplayName": "Hugo Gonzalez Labrador (gonzalhu)"
  },
  "status": "success"
}
*/

type statRes struct {
	Data   *storageStat `json:"data"`
	Status string       `json:"status"`
}

type storageStat struct {
	UploadMaxFilesize int    `json:"uploadMaxFilesize"`
	MaxHumanFilesize  string `json:"maxHumanFilesize"`
	FreeSpace         int    `json:"freeSpace"`
	UsedSpacePercent  int    `json:"usedSpacePercent"`
	Owner             string `json:"owner"`
	OwnerDisplayName  string `json:"ownerDisplayName"`
}

func (p *proxy) getStorageStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var owner string
	if user, ok := reva_api.ContextGetUser(ctx); ok {
		owner = user.AccountId
	} else if pl, ok := reva_api.ContextGetPublicLink(ctx); ok {
		owner = pl.OwnerId
	}

	gCtx := GetContextWithAuth(ctx)
	res, err := p.getStorageClient().GetQuota(gCtx, &reva_api.QuotaReq{Path: "/home"})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != reva_api.StatusCode_OK {
		p.writeError(res.Status, w, r)
		p.logger.Error("wrong grpc status", zap.Int("status", int(res.Status)))
		return
	}

	stat := &storageStat{
		UploadMaxFilesize: 10 * 1024 * 1024 * 1024, // 10 GiB
		MaxHumanFilesize:  "Upload (max. 10GB)",
		FreeSpace:         int(res.TotalBytes), // 2TiB
		UsedSpacePercent:  int((float32(res.UsedBytes) / float32(res.TotalBytes)) * 100),
		Owner:             owner,
		OwnerDisplayName:  owner,
	}
	response := &statRes{Data: stat, Status: "success"}
	encoded, err := json.Marshal(response)
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
	DisplayNameOwner     string     `json:"displayname_owner"`
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
	ShareWith            *string    `json:"share_with"`
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
	Permissions  JSONInt    `json:"permissions"`
	ExpireDate   JSONString `json:"expireDate"`
}

type Options struct {
	Logger            *zap.Logger
	TemporaryFolder   string
	ChunksFolder      string
	MaxUploadFileSize uint64
	REVAHost          string
	Router            *mux.Router

	OwnCloudHomePrefix string
	RevaHomePrefix     string

	OwnCloudSharePrefix string
	RevaSharePrefix     string

	OwnCloudPublicLinkPrefix string
	RevaPublicLinkPrefix     string

	OwnCloudPersonalProjectsPrefix string
	RevaPersonalProjectsPrefix     string

	CBOXGroupDaemonURI    string
	CBOXGroupDaemonSecret string

	MaxNumFilesForArchive int
	MaxSizeForArchive     int
	MaxViewerFileFize     int

	OverwriteHost string

	WopiServer string
	WopiSecret string

	DrawIOURL string

	CacheSize     int
	CacheEviction int

	MailServer            string
	MailServerFromAddress string
}

func (opt *Options) init() {
	if opt.TemporaryFolder == "" {
		opt.TemporaryFolder = os.TempDir()
	}
	if opt.ChunksFolder == "" {
		opt.ChunksFolder = filepath.Join(opt.TemporaryFolder, "chunks")
	}

	if opt.OwnCloudHomePrefix == "" {
		opt.OwnCloudHomePrefix = "/"
	}

	if opt.RevaHomePrefix == "" {
		opt.RevaHomePrefix = "/home"
	}

	if opt.OwnCloudSharePrefix == "" {
		opt.OwnCloudSharePrefix = "/__myshares"
	}

	if opt.RevaSharePrefix == "" {
		opt.RevaSharePrefix = "/shared-with-me"
	}

	if opt.RevaPublicLinkPrefix == "" {
		opt.RevaPublicLinkPrefix = "/public-links"
	}

	if opt.OwnCloudPersonalProjectsPrefix == "" {
		opt.OwnCloudPersonalProjectsPrefix = "/__myprojects"
	}

	if opt.RevaPersonalProjectsPrefix == "" {
		opt.RevaPersonalProjectsPrefix = "/projects"
	}

	if opt.MaxSizeForArchive == 0 {
		opt.MaxSizeForArchive = 1024 * 1024 * 1024 * 8 // 8 GiB
	}

	if opt.MaxNumFilesForArchive == 0 {
		opt.MaxNumFilesForArchive = 1000
	}
	if opt.MaxViewerFileFize == 0 {
		opt.MaxViewerFileFize = 1024 * 1024 * 10 // 10MiB
	}

	if opt.OverwriteHost == "" {
		// use system hostname
		opt.OverwriteHost, _ = os.Hostname()
	}

	if opt.DrawIOURL == "" {
		opt.DrawIOURL = "https://test-drawio.web.cern.ch"
	}

	if opt.CacheSize == 0 {
		opt.CacheSize = 1000000
	}
	if opt.CacheEviction == 0 {
		opt.CacheEviction = 86400
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

	tr := &http.Transport{
		//	DisableKeepAlives:   opts.DisableKeepAlives,
		//IdleConnTimeout:     time.Duration(opts.IdleConnTimeout) * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		//TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
		//DisableCompression:  opts.DisableCompression,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	proxy := &proxy{
		maxUploadFileSize:     int64(opt.MaxUploadFileSize),
		router:                opt.Router,
		revaHost:              opt.REVAHost,
		logger:                opt.Logger,
		cboxGroupDaemonURI:    opt.CBOXGroupDaemonURI,
		cboxGroupDaemonSecret: opt.CBOXGroupDaemonSecret,

		ownCloudHomePrefix: opt.OwnCloudHomePrefix,
		revaHomePrefix:     opt.RevaHomePrefix,

		ownCloudSharePrefix: opt.OwnCloudSharePrefix,
		revaSharePrefix:     opt.RevaSharePrefix,

		ownCloudPublicLinkPrefix: opt.OwnCloudPublicLinkPrefix,
		revaPublicLinkPrefix:     opt.RevaPublicLinkPrefix,

		ownCloudPersonalProjectsPrefix: opt.OwnCloudPersonalProjectsPrefix,
		revaPersonalProjectsPrefix:     opt.RevaPersonalProjectsPrefix,

		chunksFolder:    opt.ChunksFolder,
		temporaryFolder: opt.TemporaryFolder,

		maxNumFilesForArchive: opt.MaxNumFilesForArchive,
		maxSizeForArchive:     opt.MaxSizeForArchive,
		viewerMaxFileSize:     opt.MaxViewerFileFize,

		overwriteHost: opt.OverwriteHost,

		wopiServer: opt.WopiServer,
		wopiSecret: opt.WopiSecret,

		drawIOURL: opt.DrawIOURL,

		shareCache:    gcache.New(opt.CacheSize).LFU().Build(),
		cacheEviction: time.Duration(opt.CacheEviction) * time.Second,

		tr: tr,

		mailServer:            opt.MailServer,
		mailServerFromAddress: opt.MailServerFromAddress,
	}

	proxy.registerRoutes()
	return proxy, nil

}

type proxy struct {
	temporaryFolder   string
	chunksFolder      string
	maxUploadFileSize int64
	router            *mux.Router
	authClient        reva_api.AuthClient
	storageClient     reva_api.StorageClient
	revaHost          string
	logger            *zap.Logger

	ownCloudHomePrefix string
	revaHomePrefix     string

	ownCloudSharePrefix string
	revaSharePrefix     string

	ownCloudPublicLinkPrefix string
	revaPublicLinkPrefix     string

	ownCloudPersonalProjectsPrefix string
	revaPersonalProjectsPrefix     string

	cboxGroupDaemonURI    string
	cboxGroupDaemonSecret string

	maxNumFilesForArchive int
	maxSizeForArchive     int
	viewerMaxFileSize     int

	overwriteHost string

	wopiServer string
	wopiSecret string

	drawIOURL string

	shareCache    gcache.Cache
	cacheEviction time.Duration
	tr            *http.Transport

	mailServer            string
	mailServerFromAddress string
}

// TODO(labkode): store this global var inside the proxy
var globalConn *grpc.ClientConn

// See https://github.com/grpc/grpc/blob/master/doc/connectivity-semantics-and-api.md
// One grpc conn spans multiple TCP conns
func (p *proxy) getConn() (*grpc.ClientConn, error) {
	if globalConn != nil {
		return globalConn, nil
	}
	conn, err := grpc.Dial(p.revaHost, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	globalConn = conn
	return conn, nil
}

func (p *proxy) getTagClient() reva_api.TaggerClient {
	conn, err := p.getConn()
	if err != nil {
		panic(err)
	}
	return reva_api.NewTaggerClient(conn)
}
func (p *proxy) getStorageClient() reva_api.StorageClient {
	conn, err := p.getConn()
	if err != nil {
		panic(err)
	}
	return reva_api.NewStorageClient(conn)
}

func (p *proxy) getShareClient() reva_api.ShareClient {
	conn, err := p.getConn()
	if err != nil {
		panic(err)
	}
	return reva_api.NewShareClient(conn)
}

func (p *proxy) getAuthClient() reva_api.AuthClient {
	conn, err := p.getConn()
	if err != nil {
		panic(err)
	}
	return reva_api.NewAuthClient(conn)
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
			userRes, err := authClient.DismantleUserToken(ctx, &reva_api.TokenReq{Token: token})
			if err != nil {
				p.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				if userRes.Status != reva_api.StatusCode_OK {
					p.logger.Warn("cookie token is invalid or not longer valid", zap.Error(err))
				} else {
					user := userRes.User
					ctx = reva_api.ContextSetUser(ctx, user)
					ctx = reva_api.ContextSetAccessToken(ctx, token)
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
		gReq := &reva_api.ForgeUserTokenReq{ClientId: username, ClientSecret: password}
		gTokenRes, err := authClient.ForgeUserToken(ctx, gReq)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return

		}
		if gTokenRes.Status != reva_api.StatusCode_OK {
			p.logger.Warn("token is not valid", zap.Int("status", int(gTokenRes.Status)))
			w.Header().Set("WWW-Authenticate", "Basic Realm='owncloud credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := gTokenRes.Token
		p.logger.Info("token created", zap.String("token", token))

		gReq2 := &reva_api.TokenReq{Token: token}
		userRes, err := authClient.DismantleUserToken(ctx, gReq2)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if userRes.Status != reva_api.StatusCode_OK {
			p.logger.Error("", zap.Error(err))
			w.Header().Set("WWW-Authenticate", "Basic Realm='owncloud credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// save token into cookie for further requests
		cookie := &http.Cookie{}
		cookie.Name = "oc_sessionpassphrase"
		cookie.Value = token
		cookie.MaxAge = 3600
		http.SetCookie(w, cookie)

		user := userRes.User
		ctx = reva_api.ContextSetUser(ctx, user)
		ctx = reva_api.ContextSetAccessToken(ctx, token)
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
	revaPath := p.getRevaPath(ctx, filename)
	_, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	stream, err := p.getStorageClient().ReadRevision(gCtx, &reva_api.RevisionReq{Path: revaPath, RevKey: revision})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+path.Base(revaPath))
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
		if dcRes.Status != reva_api.StatusCode_OK {
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
	revaPath := p.getRevaPath(ctx, filename)
	res, err := p.getStorageClient().RestoreRevision(gCtx, &reva_api.RevisionReq{Path: revaPath, RevKey: revision})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != reva_api.StatusCode_OK {
		err := reva_api.NewError(reva_api.UnknownError)
		p.logger.Error("", zap.Error(err))
		p.writeError(res.Status, w, r)
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

	revaPath := p.getRevaPath(ctx, path)
	revisions, err := p.getVersionsForPath(ctx, revaPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ocRevisions := map[string]*versionEntry{}
	for _, r := range revisions {
		e := &versionEntry{
			Revision: r.RevKey,
			Name:     p.getPlainOCPath(ctx, path),
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

func (p *proxy) getVersionsForPath(ctx context.Context, path string) ([]*reva_api.Revision, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getStorageClient().ListRevisions(gCtx, &reva_api.PathReq{Path: path})
	if err != nil {
		return nil, err
	}

	revisions := []*reva_api.Revision{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != reva_api.StatusCode_OK {
			err := reva_api.NewError(reva_api.UnknownError)
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

type WalkFunc func(path string, md *reva_api.Metadata, err error) error

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
	stream, err := p.getStorageClient().ListFolder(gCtx, &reva_api.PathReq{Path: dirname})
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
		if mdRes.Status != reva_api.StatusCode_OK {
			p.logger.Error("", zap.Int("status", int(mdRes.Status)))
			return names, err
		}
		names = append(names, mdRes.Metadata.Path)
	}

	sort.Strings(names)
	return names, nil
}

// walk recursively descends path, calling walkFn.
func (p *proxy) walkRecursive(ctx context.Context, path string, md *reva_api.Metadata, walkFn WalkFunc) error {
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

func (p *proxy) getMetadata(ctx context.Context, revaPath string) (*reva_api.Metadata, error) {
	gCtx := GetContextWithAuth(ctx)
	mdRes, err := p.getStorageClient().Inspect(gCtx, &reva_api.PathReq{Path: revaPath})
	if err != nil {
		p.logger.Error("", zap.Error(err), zap.String("path", revaPath))
		return nil, err
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.logger.Error("", zap.Int("status", int(mdRes.Status)), zap.String("path", revaPath))
		// TODO(labkode): set better error code
		return nil, reva_api.NewError(reva_api.StorageNotSupportedErrorCode).WithMessage(fmt.Sprintf("status: %d", mdRes.Status))
	}
	md := mdRes.Metadata
	md.Path = p.getOCPath(ctx, md)
	md.Id = p.getOCId(ctx, md.Id)
	return md, nil
}

/*
GET https://labradorbox.cern.ch/index.php/s/jIKrtrkXCIXwg1y/download?path=%2FHugo&files=Intrinsico&downloadStartSecret=twusiwio300f6c6nkhs9n3ik9&x-access-token=<token>
Creates a TAR archive from public link
*/
func (p *proxy) downloadArchivePL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dir := r.URL.Query().Get("path")
	files := []string{}

	if r.URL.Query().Get("files") != "" {
		fullPath := path.Join(dir, r.URL.Query().Get("files"))
		fullPath = p.getRevaPath(ctx, fullPath)
		files = append(files, fullPath)
	} else {
		fileList := r.URL.Query()["files[]"]
		for _, fn := range fileList {
			fullPath := path.Join(dir, fn)
			fullPath = p.getRevaPath(ctx, fullPath)
			files = append(files, fullPath)

		}
	}

	// if only one file, trigger normal download
	if len(files) == 1 {
		md, err := p.getMetadata(ctx, files[0])
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !md.IsDir {
			mux.Vars(r)["path"] = md.Path
			p.get(w, r)
			return

		}
	}

	// if files is empty means that we need to download the whole content of dir or
	// if it is a file, only the file
	if len(files) == 0 {
		revaPath := p.getRevaPath(ctx, dir)
		md, err := p.getMetadata(ctx, revaPath)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if md.IsDir {
			files = append(files, revaPath)
		} else {
			mux.Vars(r)["path"] = dir
			p.get(w, r)
			return
		}
	}

	// we are going to download more than 1 file or directory.
	// we calculate summ size and number of files (recursively relying on tree size and container)
	// to not overload the serve with heavy archive downloads
	var fileCount int
	var sizeCount int
	for _, fn := range files {
		md, err := p.getMetadata(ctx, fn)
		if err != nil {
			p.logger.Warn("error getting md for file in archive, skiping...")
			continue
		}
		sizeCount += int(md.Size)

		if !md.IsDir {
			fileCount++
		} else {
			if md.TreeCount != 0 {
				fileCount += int(md.TreeCount)
			} else {
				fileCount++
			}
		}
	}

	if fileCount > p.maxNumFilesForArchive {
		p.logger.Warn("exceeded max number of files for archiving", zap.Int("max", p.maxNumFilesForArchive), zap.Int("found", fileCount))
		w.WriteHeader(http.StatusBadRequest)
		msg := fmt.Sprintf("You are trying to download an archive (tar/zip) that contains %s files, which exceed our limit of %d.\nTry using the sync client to get a copy of your files", fileCount, p.maxNumFilesForArchive)
		w.Write([]byte(msg))
		return
	}

	if sizeCount > p.maxSizeForArchive {
		p.logger.Warn("exceeded max aggregated size of files for archiving", zap.Int("max", p.maxSizeForArchive), zap.Int("computed_size", sizeCount))
		w.WriteHeader(http.StatusBadRequest)
		msg := fmt.Sprintf("You are trying to download an archive (tar/zip) that has a size of %d bytes, which exceed our limit of %d bytes.\nTry using the sync client to get a copy of your files", sizeCount, p.maxSizeForArchive)
		w.Write([]byte(msg))
		return
	}

	// TODO(labkode): add request ID to the archive name so we can trace back archive.
	archiveName := "download.tar"
	if len(files) == 1 && dir != "/" {
		archiveName = path.Base(files[0]) + ".tar"
	}

	p.logger.Debug("archive name: " + archiveName)

	// TODO(labkode): check for size because once the data is being written to the client we cannot override the headers.

	// if downloadStartSecret is set in the query param we need to set the cookie ocDownloadStarted with same value.
	if r.URL.Query().Get("downloadStartSecret") != "" {
		http.SetCookie(w, &http.Cookie{
			Name:    "ocDownloadStarted",
			Value:   r.URL.Query().Get("downloadStartSecret"),
			Path:    "/",
			Expires: time.Now().Add(time.Second * 30)})
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", archiveName))
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	gCtx := GetContextWithAuth(ctx)

	tw := tar.NewWriter(w)
	defer tw.Close()
	for _, fn := range files {
		err := p.Walk(ctx, fn, func(path string, md *reva_api.Metadata, err error) error {
			if err != nil {
				return err
			}

			p.logger.Debug("walking", zap.String("filename", path))
			hdr := &tar.Header{
				Name:    strings.TrimPrefix(md.Path, "/"),
				Mode:    0644,
				ModTime: time.Unix(int64(md.Mtime), 0),
			}

			if md.IsDir {
				hdr.Typeflag = tar.TypeDir
				hdr.Mode = 0755
				hdr.Name += "/"
			} else {
				hdr.Typeflag = tar.TypeReg
				hdr.Size = int64(md.Size)
			}

			// tar archive gets corrupted is header name is empty
			if md.Path != "" {
				if err := tw.WriteHeader(hdr); err != nil {
					p.logger.Error("", zap.Error(err), zap.String("fn", fn))
					return err
				}
			}

			// if file, write file contents into the tar archive
			if !md.IsDir {

				revaPath := p.getRevaPath(ctx, md.Path)
				stream, err := p.getStorageClient().ReadFile(gCtx, &reva_api.PathReq{Path: revaPath})
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
					if dcRes.Status != reva_api.StatusCode_OK {
						p.logger.Error("", zap.Int("status", int(dcRes.Status)))
						return reva_api.NewError(reva_api.StorageNotSupportedErrorCode)
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
GET http://labradorbox.cern.ch/cernbox/index.php/apps/files/ajax/download.php?dir=/&files[]=welcome.txt&files[]=signed contract.pdf&files[]=peter.txt&downloadStartSecret=k9ubkisonib HTTP/1.1
Creates a TAR archive
*/
func (p *proxy) downloadArchive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dir := r.URL.Query().Get("dir")
	plPath := r.URL.Query().Get("path")
	files := []string{}

	if dir == "" {
		if plPath == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		dir = plPath
	}

	if r.URL.Query().Get("files") != "" {
		fullPath := path.Join(dir, r.URL.Query().Get("files"))
		fullPath = p.getRevaPath(ctx, fullPath)
		files = append(files, fullPath)
	} else {
		fileList := r.URL.Query()["files[]"]
		for _, fn := range fileList {
			fullPath := path.Join(dir, fn)
			fullPath = p.getRevaPath(ctx, fullPath)
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

	// we are going to download more than 1 file or directory.
	// we calculate summ size and number of files (recursively relying on tree size and container)
	// to not overload the serve with heavy archive downloads
	var fileCount int
	var sizeCount int
	for _, fn := range files {
		md, err := p.getMetadata(ctx, fn)
		if err != nil {
			p.logger.Warn("error getting md for file in archive, skiping...")
			continue
		}
		sizeCount += int(md.Size)

		if !md.IsDir {
			fileCount++
		} else {
			if md.TreeCount != 0 {
				fileCount += int(md.TreeCount)
			} else {
				fileCount++
			}
		}
	}

	if fileCount > p.maxNumFilesForArchive {
		p.logger.Warn("exceeded max number of files for archiving", zap.Int("max", p.maxNumFilesForArchive), zap.Int("found", fileCount))
		w.WriteHeader(http.StatusBadRequest)
		msg := fmt.Sprintf("You are trying to download an archive (tar/zip) that contains %s files, which exceed our limit of %d.\nTry using the sync client to get a copy of your files", fileCount, p.maxNumFilesForArchive)
		w.Write([]byte(msg))
		return
	}

	if sizeCount > p.maxSizeForArchive {
		p.logger.Warn("exceeded max aggregated size of files for archiving", zap.Int("max", p.maxSizeForArchive), zap.Int("computed_size", sizeCount))
		w.WriteHeader(http.StatusBadRequest)
		msg := fmt.Sprintf("You are trying to download an archive (tar/zip) that has a size of %d bytes, which exceed our limit of %d bytes.\nTry using the sync client to get a copy of your files", sizeCount, p.maxSizeForArchive)
		w.Write([]byte(msg))
		return
	}

	// if downloadStartSecret is set in the query param we need to set the cookie ocDownloadStarted with same value.
	if r.URL.Query().Get("downloadStartSecret") != "" {
		http.SetCookie(w, &http.Cookie{
			Name:    "ocDownloadStarted",
			Value:   r.URL.Query().Get("downloadStartSecret"),
			Path:    "/",
			Expires: time.Now().Add(time.Second * 30)})
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", archiveName))
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	gCtx := GetContextWithAuth(ctx)

	tw := tar.NewWriter(w)
	defer tw.Close()
	for _, fn := range files {
		err := p.Walk(ctx, fn, func(path string, md *reva_api.Metadata, err error) error {
			if err != nil {
				return err
			}

			p.logger.Debug("walking", zap.String("filename", path))
			hdr := &tar.Header{
				Name:    strings.TrimPrefix(md.Path, "/"),
				Mode:    0644,
				ModTime: time.Unix(int64(md.Mtime), 0),
			}

			if md.IsDir {
				hdr.Typeflag = tar.TypeDir
				hdr.Mode = 0755
				hdr.Name += "/"
			} else {
				hdr.Typeflag = tar.TypeReg
				hdr.Size = int64(md.Size)
			}

			if err := tw.WriteHeader(hdr); err != nil {
				p.logger.Error("", zap.Error(err), zap.String("fn", fn))
				return err
			}

			// if file, write file contents into the tar archive
			if !md.IsDir {

				revaPath := p.getRevaPath(ctx, md.Path)
				stream, err := p.getStorageClient().ReadFile(gCtx, &reva_api.PathReq{Path: revaPath})
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
					if dcRes.Status != reva_api.StatusCode_OK {
						p.logger.Error("", zap.Int("status", int(dcRes.Status)))
						return reva_api.NewError(reva_api.StorageNotSupportedErrorCode)
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
	revaPath := p.getRevaPath(ctx, path)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	md.Path = p.getOCPath(ctx, md)

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
	revaPath := p.getRevaPath(ctx, p.ownCloudHomePrefix)
	stream, err := p.getStorageClient().ListRecycle(gCtx, &reva_api.PathReq{Path: revaPath})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	entries := []*reva_api.RecycleEntry{}
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

		if res.Status != reva_api.StatusCode_OK {
			err := reva_api.NewError(reva_api.UnknownError)
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		entry := res.RecycleEntry
		entry.RestorePath = p.getPlainOCPath(ctx, entry.RestorePath)
		entries = append(entries, res.RecycleEntry)
	}

	trashbinEntries := []*trashbinEntry{}
	for _, e := range entries {
		te := &trashbinEntry{
			ID:          e.RestoreKey,
			Path:        e.RestorePath,
			Permissions: 0,
			Name:        path.Base(e.RestorePath),
			Mimetype:    reva_api.DetectMimeType(e.IsDir, e.RestorePath),
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
		revaPath := p.getRevaPath(ctx, f)
		tokens := strings.Split(revaPath, ".")
		// the token after the last . is the restore key
		if len(tokens) == 0 {
			err := reva_api.NewError(reva_api.UnknownError).WithMessage(fmt.Sprintf("restore key is invalid. tokens: %+v", tokens))
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

	var statusMsg string = "success"
	var errorMsg string = ""
	if len(failedEntries) > 0 {
		statusMsg = "error"
		errorMsg = "Cannot restore file(s)"
	}
	res := &restoreResponse{Status: statusMsg, Data: &restoreData{Message: errorMsg, Success: restoredEntries, Error: failedEntries}}
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

func (p *proxy) getRecycleEntries(ctx context.Context) ([]*reva_api.RecycleEntry, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getStorageClient().ListRecycle(gCtx, &reva_api.PathReq{Path: "/"})
	if err != nil {
		return nil, err
	}

	entries := []*reva_api.RecycleEntry{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != reva_api.StatusCode_OK {
			err := reva_api.NewError(reva_api.UnknownError)
			return nil, err
		}
		entry := res.RecycleEntry
		entry.RestorePath = p.getPlainOCPath(ctx, entry.RestorePath)
		entries = append(entries, entry)
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
}
*/
type restoreResponse struct {
	Status string       `json:"status"`
	Data   *restoreData `json:"data"`
}

type restoreData struct {
	Message string           `json:"message"`
	Success []*restoredEntry `json:"success"`
	Error   []*restoredEntry `json:"error"`
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
	res, err := p.getStorageClient().RestoreRecycleEntry(gCtx, &reva_api.RecycleEntryReq{RestoreKey: restoreKey})
	if err != nil {
		return err
	}

	if res.Status != reva_api.StatusCode_OK {
		return reva_api.NewError(reva_api.UnknownError).WithMessage(fmt.Sprintf("status: %d", res.Status))

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

	revaPath := p.getRevaPath(ctx, path)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO(labkode): check that sent mtime is bigger than stored one, else means a conflict and we do not override :)

	gCtx := GetContextWithAuth(ctx)
	txInfoRes, err := p.getStorageClient().StartWriteTx(gCtx, &reva_api.EmptyReq{})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if txInfoRes.Status != reva_api.StatusCode_OK {
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
			dc := &reva_api.TxChunk{
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
	if writeSummaryRes.Status != reva_api.StatusCode_OK {
		p.writeError(writeSummaryRes.Status, w, r)
		return
	}

	// all the chunks have been sent, we need to close the tx
	emptyRes, err := p.getStorageClient().FinishWriteTx(gCtx, &reva_api.TxEnd{Path: revaPath, TxId: txInfo.TxId})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if emptyRes.Status != reva_api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	md, err = p.getMetadata(ctx, revaPath)
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

	revaPath := p.getRevaPath(ctx, fullPath)
	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO(labkode): stop loading huge files, set max to 1mib?
	if int(md.Size) > p.viewerMaxFileSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		p.logger.Warn("file is too big to be opened in the browser", zap.Int("max_size", p.viewerMaxFileSize), zap.Int("file_size", int(md.Size)))
		msg := fmt.Sprintf("The file is too big to be opened in the browser (maximum size is %d  bytes)", p.viewerMaxFileSize)
		w.Write([]byte(fmt.Sprintf(`{ "message": "%s" }`, msg)))
		return
	}

	gCtx := GetContextWithAuth(ctx)
	pathReq := &reva_api.PathReq{Path: revaPath}
	stream, err := p.getStorageClient().ReadFile(gCtx, pathReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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
		if dcRes.Status != reva_api.StatusCode_OK {
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
	res := &LoadFileResponse{
		FileContents: string(fileContents),
		MTime:        int(md.Mtime),
		Mime:         md.Mime,
		Writable:     !md.IsReadOnly,
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
	p.logger.Info("jeje", zap.String("uri", p.cboxGroupDaemonURI), zap.String("url", url))
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
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Expires", "0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)

}

func (p *proxy) createPublicLinkShare(ctx context.Context, newShare *NewShareOCSRequest, readOnly, dropOnly bool, expiration int64, w http.ResponseWriter, r *http.Request) {
	gCtx := GetContextWithAuth(ctx)
	newLinkReq := &reva_api.NewLinkReq{
		Path:     newShare.Path,
		ReadOnly: readOnly,
		DropOnly: dropOnly,
		Password: newShare.Password.Value,
		Expires:  uint64(expiration),
	}
	publicLinkRes, err := p.getShareClient().CreatePublicLink(gCtx, newLinkReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if publicLinkRes.Status != reva_api.StatusCode_OK {
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

func (p *proxy) createFolderShare(ctx context.Context, newShare *NewShareOCSRequest, readOnly bool, w http.ResponseWriter, r *http.Request) {
	recipientType := reva_api.ShareRecipient_USER
	if newShare.ShareType == ShareTypeGroup {
		recipientType = reva_api.ShareRecipient_GROUP
	}

	recipient := &reva_api.ShareRecipient{
		Identity: newShare.ShareWith,
		Type:     recipientType,
	}

	newFolderShareReq := &reva_api.NewFolderShareReq{
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
	if folderShareRes.Status != reva_api.StatusCode_OK {
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
	ctx := r.Context()
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

		newShare.Path = r.Form.Get("path")
		newShare.ShareWith = r.Form.Get("shareWith")

		var shareType ShareType
		shareTypeString := r.Form.Get("shareType")
		if shareTypeString == "0" {
			shareType = ShareTypeUser
		} else if shareTypeString == "1" {
			shareType = ShareTypeGroup
		} else if shareTypeString == "3" {
			shareType = ShareTypePublicLink
		}
		newShare.ShareType = shareType

		permissions := r.Form.Get("permissions")
		permissionsJSON := JSONInt{}
		if permissions != "" {
			perm, err := strconv.ParseInt(permissions, 10, 64)
			if err != nil {
				p.logger.Error("", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			permissionsJSON.Value = int(perm)
			permissionsJSON.Valid = true
			permissionsJSON.Set = true

		}
		newShare.Permissions = permissionsJSON

		// convert expiration and password fields to JSONString and JSONInt
		password := r.Form.Get("password")
		passwordJSON := JSONString{}
		if password != "" {
			passwordJSON.Value = password
			passwordJSON.Set = true
			passwordJSON.Valid = true
		}
		newShare.Password = passwordJSON

		expireDate := r.Form.Get("expireDate")
		expireDateJSON := JSONString{}
		if expireDate != "" {
			expireDateJSON.Value = expireDate
			expireDateJSON.Set = true
			expireDateJSON.Valid = true
		}
		newShare.ExpireDate = expireDateJSON

	}

	newShare.Path, ctx = p.stripCBOXMappedPath(r, newShare.Path)
	newShare.Path = p.getRevaPath(ctx, newShare.Path)

	var readOnly bool = true
	var dropOnly bool = false
	if newShare.Permissions.Set && Permission(newShare.Permissions.Value) >= PermissionReadWrite {
		readOnly = false
		dropOnly = false
	} else if newShare.Permissions.Set && Permission(newShare.Permissions.Value) >= PermissionDropOnly {
		readOnly = false
		dropOnly = true
	} else {
		readOnly = true
		dropOnly = false
	}

	var expiration int64
	if newShare.ExpireDate.Set && newShare.ExpireDate.Value != "" {
		t, err := time.Parse("02-01-2006", newShare.ExpireDate.Value)
		if err == nil {
			expiration = t.Unix()
		} else {
			p.logger.Warn("expire date format is not 02-01-2006", zap.Error(err))
			t, err = time.Parse("2006-01-02", newShare.ExpireDate.Value)
			if err != nil {
				p.logger.Warn("expire date format is not 2006-01-02", zap.Error(err))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			expiration = t.Unix()
		}
	}

	// check that path exists
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getStorageClient().Inspect(gCtx, &reva_api.PathReq{Path: newShare.Path})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != reva_api.StatusCode_OK {
		p.writeError(res.Status, w, r)
		return
	}

	md := res.Metadata
	newShare.Name = path.Base(md.Path)

	if newShare.ShareType == ShareTypePublicLink {
		p.createPublicLinkShare(ctx, newShare, readOnly, dropOnly, expiration, w, r)
		return
	} else if newShare.ShareType == ShareTypeUser || newShare.ShareType == ShareTypeGroup {
		p.createFolderShare(ctx, newShare, readOnly, w, r)
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
	onlySharedWithOthers := r.URL.Query().Get("only_shared_with_others") == "true"
	onlySharedByLink := r.URL.Query().Get("only_shared_by_link") == "true"
	originalPath := r.URL.Query().Get("path")
	path, ctx := p.stripCBOXMappedPath(r, originalPath)

	sharedWithMe := r.URL.Query().Get("shared_with_me")

	if sharedWithMe == "true" {
		p.getReceivedShares(w, r, path)
		return
	}

	ocsShares := []*OCSShare{}

	if onlySharedByLink {
		publicLinks, err := p.getPublicLinkShares(ctx, path)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ocsShares = publicLinks

	} else if onlySharedWithOthers {
		folderShares, err := p.getFolderShares(ctx, path)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return

		}
		ocsShares = folderShares
	} else {
		publicLinks, err := p.getPublicLinkShares(ctx, path)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ocsShares = publicLinks

		folderShares, err := p.getFolderShares(ctx, path)
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return

		}

		ocsShares = append(ocsShares, folderShares...)
	}

	meta := &ResponseMeta{Status: "ok", StatusCode: 100}
	payload := &OCSPayload{Meta: meta, Data: ocsShares}
	ocsRes := &OCSResponse{OCS: payload}
	encoded, err := json.Marshal(ocsRes)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Expires", "0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(encoded)
}

func (p *proxy) getPublicLinkShares(ctx context.Context, onlyForPath string) ([]*OCSShare, error) {
	gCtx := GetContextWithAuth(ctx)

	var revaPath string
	if onlyForPath != "" {
		revaPath = p.getRevaPath(ctx, onlyForPath)
	}

	stream, err := p.getShareClient().ListPublicLinks(gCtx, &reva_api.ListPublicLinksReq{Path: revaPath})
	if err != nil {
		return nil, err
	}

	publicLinks := []*reva_api.PublicLink{}
	for {
		plr, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if plr.Status != reva_api.StatusCode_OK {
			return nil, err
		}
		publicLinks = append(publicLinks, plr.PublicLink)

	}

	ocsShares := []*OCSShare{}
	for _, pl := range publicLinks {
		ocsShare, err := p.publicLinkToOCSShare(ctx, pl)
		if err != nil {
			p.logger.Warn("cannot convert public link to ocs share", zap.Error(err), zap.String("pl", fmt.Sprintf("%+v", pl)))
			continue
		}
		ocsShares = append(ocsShares, ocsShare)
	}
	return ocsShares, nil

}

func (p *proxy) getSharedMountPath(ctx context.Context, share *reva_api.FolderShare) string {
	return path.Join(p.ownCloudSharePrefix, fmt.Sprintf("%s (id:%s)", share.Target, share.Id))
}

func (p *proxy) getReceivedFolderShares(ctx context.Context) ([]*OCSShare, error) {
	gCtx := GetContextWithAuth(ctx)
	stream, err := p.getShareClient().ListReceivedShares(gCtx, &reva_api.EmptyReq{})
	if err != nil {
		return nil, err
	}

	folderShares := []*reva_api.FolderShare{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != reva_api.StatusCode_OK {
			return nil, err
		}
		folderShares = append(folderShares, res.Share)

	}

	ocsShares := []*OCSShare{}
	for _, share := range folderShares {
		ocsShare, err := p.receivedFolderShareToOCSShare(ctx, share)
		if err != nil {
			p.logger.Warn("cannot convert folder share to ocs share", zap.Error(err), zap.String("folder share", fmt.Sprintf("%+v", share)))
			continue
		}
		ocsShares = append(ocsShares, ocsShare)
	}
	return ocsShares, nil

}

func (p *proxy) getFolderShares(ctx context.Context, onlyForPath string) ([]*OCSShare, error) {
	gCtx := GetContextWithAuth(ctx)

	var revaPath string
	if onlyForPath != "" {
		revaPath = p.getRevaPath(ctx, onlyForPath)
	}

	stream, err := p.getShareClient().ListFolderShares(gCtx, &reva_api.ListFolderSharesReq{Path: revaPath})
	if err != nil {
		return nil, err
	}

	folderShares := []*reva_api.FolderShare{}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if res.Status != reva_api.StatusCode_OK {
			return nil, err
		}
		folderShares = append(folderShares, res.FolderShare)

	}

	ocsShares := []*OCSShare{}
	for _, share := range folderShares {
		ocsShare, err := p.folderShareToOCSShare(ctx, share)
		if err != nil {
			p.logger.Warn("cannot convert folder share to ocs share", zap.Error(err), zap.String("folder share", fmt.Sprintf("%+v", share)))
			continue
		}
		ocsShares = append(ocsShares, ocsShare)
	}
	return ocsShares, nil

}

func (p *proxy) receivedFolderShareToOCSShare(ctx context.Context, share *reva_api.FolderShare) (*OCSShare, error) {
	ocPath := p.getSharedMountPath(ctx, share)
	revaPath := p.getRevaPath(ctx, ocPath)
	md, err := p.getCachedMetadata(ctx, revaPath)
	if err != nil {
		return nil, err
	}

	var itemType ItemType = ItemTypeFolder
	shareType := ShareTypeUser
	if share.Recipient.Type == reva_api.ShareRecipient_GROUP {
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

	targetPath := path.Join(p.ownCloudSharePrefix, share.Target+fmt.Sprintf(" (id:%s)", share.Id))
	ocsShare := &OCSShare{
		ShareType:            shareType,
		ID:                   share.Id,
		DisplayNameFileOwner: share.OwnerId,
		DisplayNameOwner:     share.OwnerId,
		FileSource:           md.Id,
		FileTarget:           targetPath,
		ItemSource:           md.Id,
		ItemType:             itemType,
		MimeType:             mimeType,
		Path:                 targetPath,
		Permissions:          permissions,
		ShareTime:            int(share.Mtime),
		State:                ShareStateAccepted,
		UIDFileOwner:         share.OwnerId,
		UIDOwner:             share.OwnerId,
		ShareWith:            &shareWith,
		ShareWithDisplayName: shareWith,
	}
	return ocsShare, nil
}
func (p *proxy) folderShareToOCSShare(ctx context.Context, share *reva_api.FolderShare) (*OCSShare, error) {
	// TODO(labkode): harden check
	user, _ := reva_api.ContextGetUser(ctx)
	owner := user.AccountId

	md, err := p.getMetadata(ctx, share.Path)
	if err != nil {
		return nil, err
	}

	var itemType ItemType = ItemTypeFolder
	shareType := ShareTypeUser
	if share.Recipient.Type == reva_api.ShareRecipient_GROUP {
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
		FileSource:           md.Id,
		FileTarget:           md.Path,
		ItemSource:           md.Id,
		ItemType:             itemType,
		MimeType:             mimeType,
		Name:                 md.Path,
		Path:                 p.joinCBOXMappedPath(ctx, md.Path),
		Permissions:          permissions,
		ShareTime:            int(share.Mtime),
		State:                ShareStateAccepted,
		UIDFileOwner:         owner,
		UIDOwner:             owner,
		ShareWith:            &shareWith,
		ShareWithDisplayName: shareWith,
	}
	return ocsShare, nil
}
func (p *proxy) publicLinkToOCSShare(ctx context.Context, pl *reva_api.PublicLink) (*OCSShare, error) {
	// TODO(labkode): harden check
	user, _ := reva_api.ContextGetUser(ctx)
	owner := user.AccountId

	var itemType ItemType
	if pl.ItemType == reva_api.PublicLink_FOLDER {
		itemType = ItemTypeFolder
	} else {
		itemType = ItemTypeFile
	}

	var md *reva_api.Metadata
	if itemType == ItemTypeFile {
		fileMD, err := p.getMetadata(ctx, pl.Path)
		if err != nil {
			p.logger.Error("error getting the metadata for pl path: "+pl.Path, zap.Error(err))
			return nil, err
		}
		md = fileMD

	} else {
		folderMD, err := p.getMetadata(ctx, pl.Path)
		if err != nil {
			p.logger.Error("error getting the cached metadata for pl path: "+pl.Path, zap.Error(err))
			return nil, err
		}
		md = folderMD
	}

	mimeType := reva_api.DetectMimeType(reva_api.PublicLink_FOLDER == pl.ItemType, pl.Name)

	var permissions Permission
	if pl.ReadOnly {
		permissions = PermissionRead
	} else if pl.DropOnly {
		permissions = PermissionDropOnly
	} else {
		permissions = PermissionReadWrite
	}

	var shareWith string
	if pl.Protected {
		shareWith = "X"
	}
	var shareWithPointer *string
	if shareWith != "" {
		shareWithPointer = &shareWith
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
		FileSource:           md.Id,
		FileTarget:           md.Path,
		ItemSource:           md.Id,
		ItemType:             itemType,
		MimeType:             mimeType,
		Name:                 pl.Name,
		Path:                 p.joinCBOXMappedPath(ctx, md.Path),
		Permissions:          permissions,
		ShareTime:            int(pl.Mtime),
		State:                ShareStateAccepted,
		UIDFileOwner:         owner,
		UIDOwner:             owner,
		ShareWith:            shareWithPointer,
		ShareWithDisplayName: shareWith,
		Expiration:           expiration,
		URL:                  fmt.Sprintf("https://%s/index.php/s/%s", p.overwriteHost, pl.Token),
	}
	return ocsShare, nil
}

func (p *proxy) getReceivedShares(w http.ResponseWriter, r *http.Request, path string) {
	ctx := r.Context()

	ocsShares, err := p.getReceivedFolderShares(ctx)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	filtered := []*OCSShare{}
	if path != "" {
		for _, v := range ocsShares {
			if v.Path == path {
				filtered = append(filtered, v)
			}
		}
		ocsShares = filtered

	}

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
	/*
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
	*/
}

func (p *proxy) getPublicLink(ctx context.Context, id string) (*reva_api.PublicLink, error) {
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getShareClient().InspectPublicLink(gCtx, &reva_api.ShareIDReq{Id: id})
	if err != nil {
		return nil, err
	}

	if res.Status != reva_api.StatusCode_OK {
		if res.Status == reva_api.StatusCode_PUBLIC_LINK_NOT_FOUND {
			return nil, reva_api.NewError(reva_api.PublicLinkNotFoundErrorCode)
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
	if reva_api.IsErrorCode(err, reva_api.PublicLinkNotFoundErrorCode) {
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
	if reva_api.IsErrorCode(err, reva_api.FolderShareNotFoundErrorCode) {
		return nil, false, nil
	}
	return nil, false, err

}

func (p *proxy) getFolderShare(ctx context.Context, id string) (*reva_api.FolderShare, error) {
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getShareClient().GetFolderShare(gCtx, &reva_api.ShareIDReq{Id: id})
	if err != nil {
		return nil, err
	}

	if res.Status != reva_api.StatusCode_OK {
		if res.Status == reva_api.StatusCode_FOLDER_SHARE_NOT_FOUND {
			return nil, reva_api.NewError(reva_api.FolderShareNotFoundErrorCode)
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
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Expires", "0")
		w.Header().Set("Pragma", "no-cache")
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
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Expires", "0")
		w.Header().Set("Pragma", "no-cache")
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

	found, err := p.isPublicLinkShare(ctx, shareID)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if found {
		res, err := p.getShareClient().RevokePublicLink(gCtx, &reva_api.ShareIDReq{Id: shareID})
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if res.Status != reva_api.StatusCode_OK {
			p.writeError(res.Status, w, r)
			return
		}

		meta := &ResponseMeta{Status: "ok", StatusCode: 100}
		payload := &OCSPayload{Meta: meta}
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

	found, err = p.isFolderShare(ctx, shareID)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if found {
		res, err := p.getShareClient().UnshareFolder(gCtx, &reva_api.UnshareFolderReq{Id: shareID})
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if res.Status != reva_api.StatusCode_OK {
			p.writeError(res.Status, w, r)
			return
		}

		meta := &ResponseMeta{Status: "ok", StatusCode: 100}
		payload := &OCSPayload{Meta: meta}
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

	p.logger.Warn("share not found: " + shareID)
	meta := &ResponseMeta{Status: "failure", StatusCode: 404}
	payload := &OCSPayload{Meta: meta}
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

func (p *proxy) isPublicLinkShare(ctx context.Context, shareID string) (bool, error) {
	_, err := p.getPublicLink(ctx, shareID)
	if err != nil {
		if reva_api.IsErrorCode(err, reva_api.PublicLinkNotFoundErrorCode) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *proxy) isFolderShare(ctx context.Context, shareID string) (bool, error) {
	_, err := p.getFolderShare(ctx, shareID)
	if err != nil {
		if reva_api.IsErrorCode(err, reva_api.FolderShareNotFoundErrorCode) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// TODO(labkode): check for updateReadOnly
func (p *proxy) updateFolderShare(shareID string, readOnly bool, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &reva_api.UpdateFolderShareReq{Id: shareID, ReadOnly: readOnly, UpdateReadOnly: true}
	gCtx := GetContextWithAuth(ctx)
	res, err := p.getShareClient().UpdateFolderShare(gCtx, req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != reva_api.StatusCode_OK {
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

	meta := &ResponseMeta{Status: "ok", StatusCode: 100}
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
func (p *proxy) updatePublicLinkShare(shareID string, newShare *NewShareOCSRequest, updateExpiration, updatePassword, updatePermissions bool, expiration int64, readOnly, dropOnly bool, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	updateLinkReq := &reva_api.UpdateLinkReq{
		UpdateExpiration: updateExpiration,
		UpdatePassword:   updatePassword,
		UpdateReadOnly:   updatePermissions,
		ReadOnly:         readOnly,
		DropOnly:         dropOnly,
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

	if publicLinkRes.Status != reva_api.StatusCode_OK {
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

	meta := &ResponseMeta{Status: "ok", StatusCode: 100}
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

		newShare.ShareWith = r.Form.Get("shareWith")

		var shareType ShareType
		shareTypeString := r.Form.Get("shareType")
		if shareTypeString == "0" {
			shareType = ShareTypeUser
		} else if shareTypeString == "1" {
			shareType = ShareTypeGroup
		} else if shareTypeString == "3" {
			shareType = ShareTypePublicLink
		}
		newShare.ShareType = shareType

		permissionsJSON := JSONInt{}
		if permissions, ok := r.Form.Get("permissions"), len(r.Form["permissions"]) > 0; ok {
			if permissions != "" {
				perm, err := strconv.ParseInt(permissions, 10, 64)
				if err != nil {
					p.logger.Error("", zap.Error(err))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				permissionsJSON.Value = int(perm)
				permissionsJSON.Valid = true
				permissionsJSON.Set = true

			}
		}
		newShare.Permissions = permissionsJSON

		passwordJSON := JSONString{}
		if password, ok := r.Form.Get("password"), len(r.Form["password"]) > 0; ok {
			passwordJSON.Value = password
			passwordJSON.Set = true
			passwordJSON.Valid = true
		}
		newShare.Password = passwordJSON

		expireDateJSON := JSONString{}
		if expireDate, ok := r.Form.Get("expireDate"), len(r.Form["expireDate"]) > 0; ok {
			expireDateJSON.Value = expireDate
			expireDateJSON.Set = true
			expireDateJSON.Valid = true
		}
		newShare.ExpireDate = expireDateJSON

	}

	var readOnly bool = true
	var dropOnly bool = false
	if newShare.Permissions.Set && Permission(newShare.Permissions.Value) >= PermissionReadWrite {
		readOnly = false
		dropOnly = false
	} else if newShare.Permissions.Set && Permission(newShare.Permissions.Value) >= PermissionDropOnly {
		readOnly = false
		dropOnly = true
	} else {
		readOnly = true
		dropOnly = false
	}

	updateExpiration := false
	var expiration int64
	if newShare.ExpireDate.Set && newShare.ExpireDate.Value != "" {
		updateExpiration = true
		t, err := time.Parse("02-01-2006", newShare.ExpireDate.Value)
		if err == nil {
			expiration = t.Unix()
		} else {
			p.logger.Warn("expire date format is not 02-01-2006", zap.Error(err))
			t, err = time.Parse("2006-01-02", newShare.ExpireDate.Value)
			if err != nil {
				p.logger.Warn("expire date format is not 2006-01-02", zap.Error(err))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			expiration = t.Unix()
		}
	}

	updatePassword := newShare.Password.Set
	updatePermissions := newShare.Permissions.Set

	found, err := p.isPublicLinkShare(ctx, shareID)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if found {
		p.updatePublicLinkShare(shareID, newShare, updateExpiration, updatePassword, updatePermissions, expiration, readOnly, dropOnly, w, r)
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
	ctx := r.Context()
	shareID := mux.Vars(r)["share_id"]
	gCtx := GetContextWithAuth(ctx)

	client := p.getShareClient()
	req := &reva_api.ReceivedShareReq{ShareId: shareID}
	res, err := client.UnmountReceivedShare(gCtx, req)
	if err != nil {
		err = errors.Wrapf(err, "error unmounting received share: id=%s", shareID)
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status != reva_api.StatusCode_OK {
		err = errors.New("unexpected response from unmounting share")
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (p *proxy) isNotFoundError(err error) bool {
	return reva_api.IsErrorCode(err, reva_api.StorageNotFoundErrorCode)
}

func (p *proxy) writeError(status reva_api.StatusCode, w http.ResponseWriter, r *http.Request) {
	p.logger.Warn("write error", zap.Int("status", int(status)))
	if status == reva_api.StatusCode_STORAGE_NOT_FOUND {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if status == reva_api.StatusCode_STORAGE_PERMISSIONDENIED {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
}

func getUserFromContext(ctx context.Context) (*reva_api.User, error) {
	u, ok := reva_api.ContextGetUser(ctx)
	if !ok {
		return nil, reva_api.NewError(reva_api.ContextUserRequiredError)
	}
	return u, nil
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
	PermissionDropOnly  Permission = 4

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

func (p *proxy) renderPublicLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := mux.Vars(r)["token"]

	var password string
	if r.Method == "POST" { // password has been set in password form
		if err := r.ParseForm(); err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		password = r.Form.Get("password")
	}

	client := p.getAuthClient()
	res, err := client.ForgePublicLinkToken(ctx, &reva_api.ForgePublicLinkTokenReq{Token: token, Password: password})
	if err != nil {
		// render link not found template
		p.logger.Error("", zap.Error(err))
		w.Write([]byte(publicLinkTemplateNotFound))
		return
	}

	if res.Status != reva_api.StatusCode_OK {
		tpl, err := template.New("public_link_password").Parse(publicLinkTemplatePassword)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			p.logger.Error("", zap.Error(err))
			return
		}

		tpl.Execute(w, nil)
		return
	}

	res2, err := client.DismantlePublicLinkToken(ctx, &reva_api.TokenReq{Token: res.Token})
	if err != nil {
		// render link not found template
		p.logger.Error("", zap.Error(err))
		w.Write([]byte(publicLinkTemplateNotFound))
		return
	}
	if res.Status != reva_api.StatusCode_OK {
		// render link not found template
		p.logger.Error("", zap.Error(err))
		w.Write([]byte(publicLinkTemplateNotFound))
		return
	}

	pl := res2.PublicLink
	ctx = reva_api.ContextSetPublicLink(ctx, pl)
	ctx = reva_api.ContextSetPublicLinkToken(ctx, res.Token)

	revaPath := p.getRevaPath(ctx, "/")

	md, err := p.getMetadata(ctx, revaPath)
	if err != nil {
		p.logger.Error("error getting metadata for public link", zap.Error(err))
		w.Write([]byte(publicLinkTemplateNotFound))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	if pl.ItemType == reva_api.PublicLink_FOLDER {
		data := struct {
			Token         string
			AccessToken   string
			Note          string
			OverwriteHost string
		}{AccessToken: res.Token, Token: token, Note: "The CERN Cloud Storage", OverwriteHost: p.overwriteHost}

		if pl.DropOnly {
			tpl, err := template.New("public_link_drop_only").Parse(publicLinkDropOnly)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				p.logger.Error("", zap.Error(err))
				return
			}
			tpl.Execute(w, data)

		} else {
			tpl, err := template.New("public_link").Parse(publicLinkTemplate)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				p.logger.Error("", zap.Error(err))
				return
			}

			tpl.Execute(w, data)
		}
		return
	}

	data := struct {
		Token         string
		AccessToken   string
		ShareName     string
		Size          int
		Mime          string
		OverwriteHost string
	}{AccessToken: res.Token, Token: token, ShareName: pl.Name, Size: int(md.Size), Mime: md.Mime, OverwriteHost: p.overwriteHost}

	tpl, err := template.New("public_link_file").Parse(publicLinkTemplateFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		p.logger.Error("", zap.Error(err))
		return
	}

	tpl.Execute(w, data)
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

func (p *proxy) getPublicPreview(w http.ResponseWriter, r *http.Request) {
	v, _ := gourl.QueryUnescape(r.URL.Query().Get("file"))
	mux.Vars(r)["path"] = path.Clean(v)
	p.getPreview(w, r)
}

// TODO(labkode): refactor getGalleryPreview and getPreview
func (p *proxy) getGalleryPreview(w http.ResponseWriter, r *http.Request) {
	p.logger.Info("get request for gallery preview")
	ctx := r.Context()
	reqPath := mux.Vars(r)["path"]
	widthString := r.URL.Query().Get("width")
	heightString := r.URL.Query().Get("height")

	width, err := strconv.ParseInt(widthString, 10, 64)
	if err != nil {
		p.logger.Warn("", zap.String("x", widthString))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	height, err := strconv.ParseInt(heightString, 10, 64)
	if err != nil {
		p.logger.Warn("", zap.String("y", heightString))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	revaPath := p.getRevaPath(ctx, reqPath)
	gCtx := GetContextWithAuth(ctx)
	gReq := &reva_api.PathReq{Path: revaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}

	md := mdRes.Metadata
	md.Path = p.getOCPath(ctx, md)
	if md.IsDir {
		p.logger.Warn("file is a folder")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	// check if the file is already stored
	key := fmt.Sprintf("%s-%s-%d-%d", reqPath, md.Etag, width, height)
	thumbname := getMD5Hash(key)
	target := path.Join(p.temporaryFolder, thumbname)
	p.logger.Info("preparing preview", zap.String("path", reqPath), zap.String("key", key), zap.String("target", target))

	if _, err := os.Stat(target); err == nil {
		p.logger.Info("preview found on disk for path", zap.String("path", reqPath), zap.String("preview", target))
		fd, err := os.Open(target)
		defer fd.Close()
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", md.Mime)
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
		io.Copy(w, fd)
		return
	}

	// TODO(labkode): check for size limit
	p.logger.Info("generating preview for path", zap.String("path", reqPath), zap.String("preview", target))

	stream, err := p.getStorageClient().ReadFile(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	contents := []byte{}
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
		if dcRes.Status != reva_api.StatusCode_OK {
			p.writeError(dcRes.Status, w, r)
			return
		}

		dc := dcRes.DataChunk

		if dc != nil {
			if dc.Length > 0 {
				contents = append(contents, dc.Data...)
			}
		}
	}

	basename := path.Base(reqPath)
	format, err := imaging.FormatFromFilename(basename)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var rotate int
	var flip FlipDirection
	reader := bytes.NewReader(contents)

	ex, err := exif.Decode(reader)
	if err == nil {
		rotate, flip = exifOrientation(ex)
	}

	_, err = reader.Seek(0, 0)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	config, _, err := image.DecodeConfig(reader)
	if err != nil {
		p.logger.Error("error decoding image config", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var maxH int64 = 1200
	var maxW int64 = 1200

	sourceW := int64(config.Width)
	sourceH := int64(config.Height)

	sourceRatio := float64(sourceW) / float64(sourceH)
	thumbRatio := float64(maxW) / float64(maxH)

	// adjust aspect ratio
	if sourceW <= maxW && sourceH < maxH {
		width = sourceW
		height = sourceH
	} else if thumbRatio > sourceRatio {
		width = int64(float64(maxH) * sourceRatio)
		height = maxH
	} else {
		width = maxW
		height = int64(float64(maxW) / sourceRatio)
	}

	_, err = reader.Seek(0, 0)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	img, err := imaging.Decode(reader)
	if err != nil {
		panic(err)
	}

	img = imaging.Thumbnail(img, int(width), int(height), imaging.Linear)

	// apply transformations
	if rotate > 0 {
		img = imaging.Rotate(img, float64(rotate), color.Transparent)
	}
	if flip == FlipVertical {
		img = imaging.FlipV(img)
	} else if flip == FlipHorizontal {
		img = imaging.FlipH(img)
	}

	fd, err := os.Create(target)
	defer fd.Close()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = imaging.Encode(fd, img, format)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fd.Close()
	// TODO(labkode): use a multi-writer to write to respone and to disk at same time

	w.Header().Set("Content-Type", md.Mime)
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

	fd, err = os.Open(target)
	defer fd.Close()
	io.Copy(w, fd)

}

func (p *proxy) getPreview(w http.ResponseWriter, r *http.Request) {
	p.logger.Info("get request for preview")
	ctx := r.Context()
	reqPath := path.Clean(mux.Vars(r)["path"])
	//etag := r.URL.Query().Get("c")
	widthString := r.URL.Query().Get("x")
	heightString := r.URL.Query().Get("y")

	width, err := strconv.ParseInt(widthString, 10, 64)
	if err != nil {
		p.logger.Warn("", zap.String("x", widthString))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	height, err := strconv.ParseInt(heightString, 10, 64)
	if err != nil {
		p.logger.Warn("", zap.String("y", heightString))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gCtx := GetContextWithAuth(ctx)
	revaPath := p.getRevaPath(ctx, reqPath)
	gReq := &reva_api.PathReq{Path: revaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}

	md := mdRes.Metadata
	if md.IsDir {
		p.logger.Warn("file is a folder")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	// check if the file is already stored
	key := fmt.Sprintf("%s-%s-%d-%d", reqPath, md.Etag, width, height)
	thumbname := getMD5Hash(key)
	target := path.Join(p.temporaryFolder, thumbname)
	p.logger.Info("preparing preview", zap.String("path", reqPath), zap.String("key", key), zap.String("target", target))

	if _, err := os.Stat(target); err == nil {
		p.logger.Info("preview found on disk for path", zap.String("path", reqPath), zap.String("preview", target))
		fd, err := os.Open(target)
		defer fd.Close()
		if err != nil {
			p.logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", md.Mime)
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
		io.Copy(w, fd)
		return
	}

	// TODO(labkode): check for size limit
	p.logger.Info("generating preview for path", zap.String("path", reqPath), zap.String("preview", target))

	stream, err := p.getStorageClient().ReadFile(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	contents := []byte{}
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
		if dcRes.Status != reva_api.StatusCode_OK {
			p.writeError(dcRes.Status, w, r)
			return
		}

		dc := dcRes.DataChunk

		if dc != nil {
			if dc.Length > 0 {
				contents = append(contents, dc.Data...)
			}
		}
	}

	basename := path.Base(reqPath)
	if token, ok := reva_api.ContextGetPublicLinkToken(ctx); ok && token != "" {
		if pl, ok := reva_api.ContextGetPublicLink(ctx); ok {
			if reqPath == "/" { // preview for file pl
				basename = pl.Name
			}
		}
	}

	format, err := imaging.FormatFromFilename(basename)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var rotate int
	var flip FlipDirection
	reader := bytes.NewReader(contents)

	ex, err := exif.Decode(reader)
	if err == nil {
		rotate, flip = exifOrientation(ex)
	}

	_, err = reader.Seek(0, 0)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	img, err := imaging.Decode(reader)
	if err != nil {
		panic(err)
	}

	img = imaging.Thumbnail(img, int(width), int(height), imaging.Linear)

	// apply transformations
	if rotate > 0 {
		img = imaging.Rotate(img, float64(rotate), color.Transparent)
	}
	if flip == FlipVertical {
		img = imaging.FlipV(img)
	} else if flip == FlipHorizontal {
		img = imaging.FlipH(img)
	}

	fd, err := os.Create(target)
	defer fd.Close()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = imaging.Encode(fd, img, format)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fd.Close()
	// TODO(labkode): use a multi-writer to write to respone and to disk at same time

	w.Header().Set("Content-Type", md.Mime)
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

	fd, err = os.Open(target)
	defer fd.Close()
	io.Copy(w, fd)
}

func (p *proxy) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pa := mux.Vars(r)["path"]
	isPreview := (r.URL.Query().Get("preview") == "1" || r.URL.Query().Get("forceIcon") == "1")
	if isPreview {
		p.getPreview(w, r)
		return
	}

	gCtx := GetContextWithAuth(ctx)
	revaPath := p.getRevaPath(ctx, pa)
	gReq := &reva_api.PathReq{Path: revaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}

	md := mdRes.Metadata
	md.Path = p.getOCPath(ctx, md)
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

	w.Header().Set("Content-Type", md.Mime)
	w.Header().Set("ETag", md.Etag)
	w.Header().Set("OC-FileId", md.Id)
	w.Header().Set("OC-ETag", md.Etag)
	t := time.Unix(int64(md.Mtime), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	if md.Checksum != "" {
		w.Header().Set("OC-Checksum", md.Checksum)
	}

	// if downloadStartSecret is set in the query param we need to set the cookie ocDownloadStarted with same value.
	if r.URL.Query().Get("downloadStartSecret") != "" {
		http.SetCookie(w, &http.Cookie{
			Name:    "ocDownloadStarted",
			Value:   r.URL.Query().Get("downloadStartSecret"),
			Expires: time.Now().Add(time.Second * 30)})
	}

	//w.Header().Set("Content-Disposition", "attachment; filename="+path.Base(md.Path))
	// TODO(labkode): when accesing a file pl, the path is empty, so the download appears as download, using the eos info is more friendly
	w.Header().Set("Content-Disposition", "attachment; filename=\""+path.Base(md.EosFile)+"\"")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Expires", "0")
	w.Header().Set("Pragma", "no-cache")
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
		if dcRes.Status != reva_api.StatusCode_OK {
			p.writeError(dcRes.Status, w, r)
			return
		}

		dc := dcRes.DataChunk

		if dc != nil {
			if dc.Length > 0 {
				reader = bytes.NewReader(dc.Data)
				_, err := io.CopyN(w, reader, int64(dc.Length))
				if err != nil {
					p.logger.Error("error copying data to w", zap.Error(err))
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
	revaPath := p.getRevaPath(ctx, path)
	gReq := &reva_api.PathReq{Path: revaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}
	md := mdRes.Metadata
	w.Header().Set("Content-Type", md.Mime)
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
	path = p.getRevaPath(ctx, path)

	gCtx := GetContextWithAuth(ctx)
	revaPath := p.getRevaPath(ctx, path)
	gReq := &reva_api.PathReq{Path: revaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
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
	revaPath := p.getRevaPath(ctx, path)
	gReq := &reva_api.PathReq{Path: revaPath}
	emptyRes, err := p.getStorageClient().Delete(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != reva_api.StatusCode_OK {
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
	revaPath := p.getRevaPath(ctx, path)
	gReq := &reva_api.PathReq{Path: revaPath}
	emptyRes, err := p.getStorageClient().CreateDir(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != reva_api.StatusCode_OK {
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

	destinationURL, err := gourl.ParseRequestURI(destination)
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

	var destinationPath string
	if strings.HasPrefix(destinationURL.Path, "remote.php/webdav") {
		davPrefix := "remote.php/webdav"
		index := strings.Index(destinationURL.Path, davPrefix)
		destinationPath = path.Join("/", string(destinationURL.Path[index+len(davPrefix):]))
	} else if strings.HasPrefix(destinationURL.Path, "public.php/webdav") {
		davPrefix := "public.php/webdav"
		index := strings.Index(destinationURL.Path, davPrefix)
		destinationPath = path.Join("/", string(destinationURL.Path[index+len(davPrefix):]))
	} else { // url is /remote.php/dav/gonzalhu/files
		username := mux.Vars(r)["username"]
		davPrefix := fmt.Sprintf("remote.php/dav/files/%s", username)
		index := strings.Index(destinationURL.Path, davPrefix)
		destinationPath = path.Join("/", string(destinationURL.Path[index+len(davPrefix):]))
	}

	gCtx := GetContextWithAuth(ctx)
	oldRevaPath := p.getRevaPath(ctx, oldPath)
	destinationRevaPath := p.getRevaPath(ctx, destinationPath)
	gReq := &reva_api.MoveReq{OldPath: oldRevaPath, NewPath: destinationRevaPath}
	emptyRes, err := p.getStorageClient().Move(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != reva_api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	gReq2 := &reva_api.PathReq{Path: destinationRevaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq2)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}
	md := mdRes.Metadata
	md.Path = p.getOCPath(ctx, md)

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
	revaPath := p.getRevaPath(ctx, path)
	gReq := &reva_api.PathReq{Path: revaPath}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		if mdRes.Status != reva_api.StatusCode_STORAGE_NOT_FOUND {
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
		md.Path = p.getOCPath(ctx, md)
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

	txInfoRes, err := p.getStorageClient().StartWriteTx(gCtx, &reva_api.EmptyReq{})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if txInfoRes.Status != reva_api.StatusCode_OK {
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
			dc := &reva_api.TxChunk{
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
	if writeSummaryRes.Status != reva_api.StatusCode_OK {
		p.writeError(writeSummaryRes.Status, w, r)
		return
	}

	// all the chunks have been sent, we need to close the tx
	emptyRes, err := p.getStorageClient().FinishWriteTx(gCtx, &reva_api.TxEnd{Path: revaPath, TxId: txInfo.TxId})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if emptyRes.Status != reva_api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	modifiedMdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if modifiedMdRes.Status != reva_api.StatusCode_OK {
		p.writeError(modifiedMdRes.Status, w, r)
		return
	}
	modifiedMd := modifiedMdRes.Metadata

	w.Header().Add("Content-Type", modifiedMd.Mime)
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
	path = p.getRevaPath(ctx, path)
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
	gReq := &reva_api.PathReq{Path: chunkInfo.path}
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	// if err is not found it is okay to continue
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		if mdRes.Status != reva_api.StatusCode_STORAGE_NOT_FOUND {
			p.writeError(mdRes.Status, w, r)
			return
		}
	}

	md := mdRes.Metadata
	md.Path = p.getOCPath(ctx, md)
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

	txInfoRes, err := p.getStorageClient().StartWriteTx(gCtx, &reva_api.EmptyReq{})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if txInfoRes.Status != reva_api.StatusCode_OK {
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
			dc := &reva_api.TxChunk{
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
	if writeSummaryRes.Status != reva_api.StatusCode_OK {
		p.writeError(writeSummaryRes.Status, w, r)
		return
	}

	// all the chunks have been sent, we need to close the tx
	emptyRes, err := p.getStorageClient().FinishWriteTx(gCtx, &reva_api.TxEnd{Path: chunkInfo.path, TxId: txInfo.TxId})
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if emptyRes.Status != reva_api.StatusCode_OK {
		p.writeError(emptyRes.Status, w, r)
		return
	}

	modifiedMdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if modifiedMdRes.Status != reva_api.StatusCode_OK {
		p.writeError(modifiedMdRes.Status, w, r)
		return
	}

	modifiedMd := modifiedMdRes.Metadata
	w.Header().Add("Content-Type", md.Mime)
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

	// request comes from remote.php/dav/files/gonzalhu/...
	if mux.Vars(r)["username"] != "" {
		ctx = context.WithValue(ctx, "user-dav-uri", true)
	}

	gCtx := GetContextWithAuth(ctx)
	revaPath := p.getRevaPath(ctx, path)
	gReq := &reva_api.PathReq{Path: revaPath}

	var children bool
	depth := r.Header.Get("Depth")
	// TODO(labkode) Check default for infinity header
	if depth == "1" {
		children = true
	}

	var mds []*reva_api.Metadata
	mdRes, err := p.getStorageClient().Inspect(gCtx, gReq)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mdRes.Status != reva_api.StatusCode_OK {
		p.writeError(mdRes.Status, w, r)
		return
	}
	md := mdRes.Metadata
	md.Path = p.getOCPath(ctx, md)

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
			if mdRes.Status != reva_api.StatusCode_OK {
				p.writeError(mdRes.Status, w, r)
				return
			}
			md = mdRes.Metadata
			md.Path = p.getOCPath(ctx, md)
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

func (p *proxy) mdsToXML(ctx context.Context, mds []*reva_api.Metadata) (string, error) {
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

func (p *proxy) mdToPropResponse(ctx context.Context, md *reva_api.Metadata, props ...propertyXML) (*responseXML, error) {
	propList := []propertyXML{}

	getETag := propertyXML{
		xml.Name{Space: "", Local: "d:getetag"},
		"", []byte(md.Etag)}

	// See https://github.com/owncloud/core/issues/8322
	perm := ""
	if !md.IsReadOnly {
		perm = "WCKDNV"

	}
	if md.IsShareable {
		perm += "R"
	}
	ocPermissions := propertyXML{xml.Name{Space: "", Local: "oc:permissions"},
		"", []byte(perm)}

	/*
		quotaUsedBytes := propertyXML{
			xml.Name{Space: "", Local: "d:quota-used-bytes"}, "", []byte("0")}

		quotaAvailableBytes := propertyXML{
			xml.Name{Space: "", Local: "d:quota-available-bytes"}, "",
			[]byte("1000000000")}
	*/

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
			"", []byte(md.Mime)}

	}

	// Finder needs the the getLastModified property to work.
	t := time.Unix(int64(md.Mtime), 0).UTC()
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
		ocPermissions.InnerXML = []byte(perm)
	}

	// the fileID must be xml-escaped as there are cases like public links
	// that contains a path as the file id. This path can contain &, for example,
	// which if it is not encoded properly, will result in an empty view for the user
	var fileIDEscaped bytes.Buffer
	err := xml.EscapeText(&fileIDEscaped, []byte(md.Id))
	if err != nil {
		p.logger.Error("error xml escaping oc:fileid", zap.Error(err))
		return nil, err

	}
	ocID := propertyXML{xml.Name{Space: "", Local: "oc:fileid"}, "",
		fileIDEscaped.Bytes()}

	ocDownloadURL := propertyXML{xml.Name{Space: "", Local: "oc:downloadURL"},
		"", []byte("")}

	ocDC := propertyXML{xml.Name{Space: "", Local: "oc:dDC"},
		"", []byte("")}

	propList = append(propList, getResourceType, getContentLegnth, getContentType, getLastModified, // general WebDAV properties
		getETag /*quotaAvailableBytes, quotaUsedBytes,*/, ocID, ocDownloadURL, ocDC, ocPermissions) // properties needed by ownCloud
	propList = append(propList, props...)

	// PropStat, only HTTP/1.1 200 is sent.
	propStatList := []propstatXML{}

	propStat := propstatXML{}
	propStat.Prop = propList
	propStat.Status = "HTTP/1.1 200 OK"
	propStatList = append(propStatList, propStat)

	response := responseXML{}

	// TODO(labkode): harden check for user
	if user, ok := reva_api.ContextGetUser(ctx); ok {
		var ref string

		// check for remote.php/webdav and remote.php/dav/files/gonzalhu/
		if val := ctx.Value("user-dav-uri"); val != nil {
			ref = path.Join("/remote.php/dav/files", user.AccountId, md.Path)
		} else {
			ref = path.Join("/remote.php/webdav", md.Path)
		}

		if md.IsDir {
			ref += "/"
		}

		response.Href = ref

	} else { // public link access
		response.Href = path.Join("/public.php/webdav", md.Path)
		if md.IsDir {
			response.Href = path.Join("/public.php/webdav", md.Path) + "/"
		}
	}

	// url encode response.Href
	encoded := &url.URL{Path: response.Href}
	response.Href = encoded.String()

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

// exifOrientation parses the  EXIF data in r and returns the stored
// orientation as the angle and flip necessary to transform the image.
func exifOrientation(ex *exif.Exif) (int, FlipDirection) {
	var (
		angle    int
		flipMode FlipDirection
	)
	tag, err := ex.Get(exif.Orientation)
	if err != nil {
		return 0, 0
	}
	orient, err := tag.Int(0)
	if err != nil {
		return 0, 0
	}
	switch orient {
	case topLeftSide:
		// do nothing
	case topRightSide:
		flipMode = 2
	case bottomRightSide:
		angle = 180
	case bottomLeftSide:
		angle = 180
		flipMode = 2
	case leftSideTop:
		angle = -90
		flipMode = 2
	case rightSideTop:
		angle = -90
	case rightSideBottom:
		angle = 90
		flipMode = 2
	case leftSideBottom:
		angle = 90
	}
	return angle, flipMode
}

// Exif Orientation Tag values
// Exif Orientation Tag values
// http://sylvana.net/jpegcrop/exif_orientation.html
const (
	topLeftSide     = 1
	topRightSide    = 2
	bottomRightSide = 3
	bottomLeftSide  = 4
	leftSideTop     = 5
	rightSideTop    = 6
	rightSideBottom = 7
	leftSideBottom  = 8
)

// The FlipDirection type is used by the Flip option in DecodeOpts
// to indicate in which direction to flip an image.
type FlipDirection int

// FlipVertical and FlipHorizontal are two possible FlipDirections
// values to indicate in which direction an image will be flipped.
const (
	FlipVertical FlipDirection = 1 << iota
	FlipHorizontal
)

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func GetContextWithAuth(ctx context.Context) context.Context {
	if token, ok := reva_api.ContextGetPublicLinkToken(ctx); ok && token != "" {
		header := metadata.New(map[string]string{"authorization": "pl-bearer " + token})
		return metadata.NewOutgoingContext(ctx, header)
	}

	if token, ok := reva_api.ContextGetAccessToken(ctx); ok && token != "" {
		header := metadata.New(map[string]string{"authorization": "user-bearer " + token})
		return metadata.NewOutgoingContext(ctx, header)
	}
	return ctx
}

func (p *proxy) publicLinkAuth(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := mux.Vars(r)["token"]

		// try to authenticate the link with empty password
		client := p.getAuthClient()
		res, err := client.ForgePublicLinkToken(ctx, &reva_api.ForgePublicLinkTokenReq{Token: token, Password: ""})
		if err == nil && res.Status == reva_api.StatusCode_OK {
			// inject token in request
			r.Header.Set("x-access-token", res.Token)
		}
		h(w, r)
	})
}

func (p *proxy) tokenAuth(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		normalizedPath := mux.Vars(r)["path"]
		normalizedPath = path.Join("/", path.Clean(normalizedPath))
		mux.Vars(r)["path"] = normalizedPath

		authClient := p.getAuthClient()

		// 1st: check if token comes from header
		token := r.Header.Get("X-Access-Token")

		// 2nd: check if token comes from query parameter
		if token == "" {
			token = r.URL.Query().Get("x-access-token")
		}

		// 3rd: check basic auth
		// the request public.php/webdav sends the public link token as basic auth, so
		// we cannot use basic auth first as it will try to authorize a non existing user, reducing the performance
		if token == "" {
			if username, password, ok := r.BasicAuth(); ok {
				req := &reva_api.ForgeUserTokenReq{ClientId: username, ClientSecret: password}
				res, err := authClient.ForgeUserToken(ctx, req)
				if err != nil {
					p.logger.Warn("error authentication user with basic auth", zap.String("username", username), zap.Error(err))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if res.Status != reva_api.StatusCode_OK {
					p.logger.Warn("grpc auth req failed", zap.String("username", username), zap.Int("code", int(res.Status)))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				token = res.Token
				p.logger.Info("x-access-token generated from basic auth", zap.String("username", username))
			}

		}

		if token == "" {
			p.logger.Warn("auth token not provided", zap.String("X-Access-Token", token))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// try with user token
		userRes, err := authClient.DismantleUserToken(ctx, &reva_api.TokenReq{Token: token})
		if err == nil && userRes.Status == reva_api.StatusCode_OK {
			user := userRes.User
			ctx = reva_api.ContextSetUser(ctx, user)
			ctx = reva_api.ContextSetAccessToken(ctx, token)
			r = r.WithContext(ctx)
			p.logger.Info("user authenticated with token", zap.String("account_id", user.AccountId))
			h(w, r)
			return
		}

		// try with public link token
		res, err := authClient.DismantlePublicLinkToken(ctx, &reva_api.TokenReq{Token: token})
		if err != nil {
			p.logger.Warn("", zap.Error(err), zap.String("token", token))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if res.Status != reva_api.StatusCode_OK {
			p.logger.Warn("token is invalid or not longer valid", zap.Error(err))
		}

		pl := res.PublicLink
		ctx = reva_api.ContextSetPublicLink(ctx, pl)
		ctx = reva_api.ContextSetPublicLinkToken(ctx, token)
		r = r.WithContext(ctx)
		p.logger.Info("authenticated with public link token", zap.String("token", pl.Token))
		h(w, r)
		return
	})
}

func (p *proxy) getRevaPath(ctx context.Context, ocPath string) string {
	var revaPath string

	if token, ok := reva_api.ContextGetPublicLinkToken(ctx); ok && token != "" {
		if pl, ok := reva_api.ContextGetPublicLink(ctx); ok {
			// apply  public link
			revaPath = strings.TrimPrefix(ocPath, p.ownCloudPublicLinkPrefix)
			revaPath = path.Join(p.revaPublicLinkPrefix, pl.Token, revaPath)

			// if public link is drop only we add random uuid to avoid
			// clashes on file upload.
			if pl.DropOnly {
				// if path points to publc link we do not add
				// the uuid, as the link will not be resolved.
				if ocPath != "/" {
					uuid := uuid.Must(uuid.NewV4()).String()
					dir, fn := path.Split(revaPath)
					fn = fmt.Sprintf("%s-%s", uuid, fn)
					revaPath = path.Join(dir, fn)
				}
			}
		}
	} else {
		if strings.HasPrefix(ocPath, p.ownCloudSharePrefix) {
			revaPath = strings.TrimPrefix(ocPath, p.ownCloudSharePrefix)
			// remove file target before contacting reva
			revaPath = strings.TrimPrefix(revaPath, "/")
			tokens := strings.Split(revaPath, "/")
			_, id, err := p.splitRootPath(ctx, tokens[0])
			if err != nil {
				p.logger.Error("error removing file target from ocPath", zap.Error(err), zap.String("ocPath", ocPath))
			}
			revaPath = path.Join("/", id)
			if len(tokens) > 1 {
				revaPath = path.Join(revaPath, path.Join(tokens[1:]...))
			}

			revaPath = path.Join(p.revaSharePrefix, revaPath)
		} else if strings.HasPrefix(ocPath, p.ownCloudPersonalProjectsPrefix) {
			revaPath = strings.TrimPrefix(ocPath, p.ownCloudPersonalProjectsPrefix)
			revaPath = path.Join(p.revaPersonalProjectsPrefix, revaPath)

		} else {
			// apply home default
			revaPath = strings.TrimPrefix(ocPath, p.ownCloudHomePrefix)
			revaPath = path.Join(p.revaHomePrefix, revaPath)
		}

	}

	p.logger.Debug(fmt.Sprintf("owncloud path conversion: oc(%s) => reva(%s)", ocPath, revaPath))
	return revaPath
}

func (p *proxy) getPlainOCPath(ctx context.Context, revaPath string) string {
	var ocPath string
	ocPath = strings.TrimPrefix(revaPath, p.revaHomePrefix)
	ocPath = path.Join(p.ownCloudHomePrefix, ocPath)
	p.logger.Debug(fmt.Sprintf("owncloud path conversion: reva(%s) =>oc(%s)", revaPath, ocPath))
	return ocPath
}

func (p *proxy) getOCId(ctx context.Context, id string) string {
	tokens := strings.Split(id, ":")
	// logic for home migration
	if tokens[0] == "oldhome" || strings.HasPrefix(tokens[0], "eoshome-") {
		tokens[0] = "home"
	}
	// logic for project migration
	if tokens[0] == "oldproject" || strings.HasPrefix(tokens[0], "newproject-") {
		tokens[0] = "projects"
	}
	return strings.Join(tokens, ":")
}

func (p *proxy) getOCPath(ctx context.Context, md *reva_api.Metadata) string {
	revaPath := md.Path
	var ocPath string

	if token, ok := reva_api.ContextGetPublicLinkToken(ctx); ok && token != "" {
		ocPath = strings.TrimPrefix(revaPath, p.revaPublicLinkPrefix)
		ocPath = strings.TrimPrefix(ocPath, "/")
		// vals is ["<token>", "photos", "..."]
		vals := strings.Split(ocPath, "/")
		ocPath = path.Join(p.ownCloudPublicLinkPrefix, path.Join(vals[1:]...))
	} else {
		if strings.HasPrefix(revaPath, p.revaSharePrefix) {
			ocPath = strings.TrimPrefix(revaPath, p.revaSharePrefix)
			ocPath = strings.TrimPrefix(ocPath, "/")
			tokens := strings.Split(ocPath, "/")
			tokens[0] = p.addShareTarget(ctx, tokens[0], md)
			ocPath = path.Join("/", path.Join(tokens...))
			ocPath = path.Join(p.ownCloudSharePrefix, ocPath)
		} else {
			if strings.HasPrefix(revaPath, p.revaHomePrefix) {
				ocPath = strings.TrimPrefix(revaPath, p.revaHomePrefix)
				ocPath = path.Join(p.ownCloudHomePrefix, ocPath)
			} else if strings.HasPrefix(revaPath, p.revaPersonalProjectsPrefix) {
				ocPath = strings.TrimPrefix(revaPath, p.revaPersonalProjectsPrefix)
				ocPath = path.Join(p.ownCloudPersonalProjectsPrefix, ocPath)
			} else {
				// this is migration logic, like getting shares or favs will
				// give us back the migrated id and migrated path like
				// /oldhome or eosproject-a
				if strings.HasPrefix(revaPath, "/old/project") {
					// remove oldproject prefix and replace by projects
					// revaPath is /old/project/l/labradorprojecttest/somehting/docs
					ocPath = strings.TrimPrefix(revaPath, "/old/project")
					ocPath = strings.TrimPrefix(ocPath, "/") // remove first slash
					parts := strings.Split(ocPath, "/")      // [l, labradorprojecttest, docs]
					parts[0] = ""                            // remove letter
					ocPath = path.Join("/", p.ownCloudPersonalProjectsPrefix, path.Join(parts...))
				} else if strings.HasPrefix(revaPath, "/new/project") {
					// remove newproject prefix and replace by projects
					// revaPath is /new/project/l/labradorprojecttest/somehting/docs
					ocPath = strings.TrimPrefix(revaPath, "/new/project")
					ocPath = strings.TrimPrefix(ocPath, "/") // remove first slash
					parts := strings.Split(ocPath, "/")      // [l, labradorprojecttest, docs]
					parts[0] = ""                            // remove letter
					ocPath = path.Join("/", p.ownCloudPersonalProjectsPrefix, path.Join(parts...))
				} else {
					// migration logic, strip /oldhome or /eoshome-l from reva path
					ocPath = strings.Trim(revaPath, "/")
					parts := strings.Split(ocPath, "/")
					parts[0] = ""
					ocPath = path.Join("/", p.ownCloudHomePrefix, path.Join(parts...))
				}
			}
		}
	}
	p.logger.Debug(fmt.Sprintf("owncloud path conversion: reva(%s) =>oc(%s)", revaPath, ocPath))
	return ocPath
}

func (p *proxy) splitRootPath(ctx context.Context, path string) (string, string, error) {
	loc := shareIDRegexp.FindStringIndex(path)
	if loc == nil {
		return "", "", errors.New(fmt.Sprintf("path(%s) does not match regexp", path))
	}
	shareID := path[loc[0]+4 : loc[1]-1]
	targetName := path[0:loc[0]]
	return targetName, shareID, nil
}

func (p *proxy) addShareTarget(ctx context.Context, id string, md *reva_api.Metadata) string {
	return fmt.Sprintf("%s (id:%s)", md.ShareTarget, id)

}

func execute(cmd *exec.Cmd) (string, string, int) {
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	err := cmd.Run()

	var exitStatus int
	if exiterr, ok := err.(*exec.ExitError); ok {
		// The program has exited with an exit code != 0
		// This works on both Unix and Windows. Although package
		// syscall is generally platform dependent, WaitStatus is
		// defined for both Unix and Windows and in both cases has
		// an ExitStatus() method with the same signature.
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			exitStatus = status.ExitStatus()
		}
	}
	return outBuf.String(), errBuf.String(), exitStatus
}

func (p *proxy) getCachedMetadata(ctx context.Context, path string) (*reva_api.Metadata, error) {
	v, err := p.shareCache.Get(path)
	if err == nil {
		if md, ok := v.(*reva_api.Metadata); ok {
			p.logger.Debug("ocproxy: api: getCachedMetadata: md found in cache", zap.String("path", path))
			return md, nil
		}
	}

	md, err := p.getMetadata(ctx, path)
	if err != nil {
		return nil, err
	}

	p.shareCache.SetWithExpire(path, md, p.cacheEviction)
	p.logger.Debug("ocproxy: api: getCachedMetadata: md retrieved and stored  in cache", zap.String("path", path))
	return md, nil
}
