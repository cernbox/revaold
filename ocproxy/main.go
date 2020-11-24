package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"
	"github.com/cernbox/revaold/api/canary"
	"github.com/cernbox/revaold/api/office_engine"
	"github.com/cernbox/revaold/api/otg"
	"github.com/cernbox/revaold/ocproxy/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

var gc *goconfig.GoConfig

func init() {
	hostname, _ := os.Hostname()
	gc = goconfig.New()
	gc.SetConfigName("ocproxy")
	gc.AddConfigurationPaths("/etc/ocproxy")
	gc.Add("tcp-address", "localhost:1099", "tcp addresss to listen for connections")
	gc.Add("app-log", "stderr", "file to log application information")
	gc.Add("http-log", "stderr", "file to log http log information")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error)")
	gc.Add("tls-cert", "/etc/grid-security/hostcert.pem", "TLS certificate to encrypt connections.")
	gc.Add("tls-key", "/etc/grid-security/hostkey.pem", "TLS private key to encrypt connections.")
	gc.Add("tls-enable", false, "Enable TLS for encrypting connections.")
	gc.Add("hostname", hostname, "Hostname to set in URLs, default is machine hostname")

	gc.Add("data-chunks-folder", "", "folder where to store data chunks before they are commited to REVA.")
	gc.Add("temporary-folder", "", "folder where to store temporary data. Empty means use the OS temporary folder.")
	gc.Add("thumbnails-folder", "", "folder where to store thumbnails. Empty means use the OS temporary folder.")
	gc.Add("max-upload-file-size", 8589934592, "maximum file size for upload files.")
	gc.Add("jwt-sign-key", "bar", "secret to sign JWT tokens.")
	gc.Add("reva-tcp-address", "localhost:9999", "tcp address of the REVA server.")
	gc.Add("cboxgroupd-http-address", "http://localhost:2002", "http(s) address of the CERNBox Group Daemon (cboxgroupd).")
	gc.Add("cboxgroupd-shared-secret", "bar", "shared secret to connect to the CERNBox Group Daemon (cboxgroupd).")

	gc.Add("archive-max-num-files", 1000, "maximun number of files to allow for download in archive (tar/zip)")
	gc.Add("archive-max-size", 8589934592, "maximun aggreagated size to allow for download in archive (tar/zip)")
	gc.Add("viewer-max-file-size", 10485760, "maximun file size to open files in a viewer")

	gc.Add("overwrite-host", "", "if set, overwrites the hostname of the machine, usually used when server is after a proxy")
	gc.Add("wopi-server", "http://wopihost.example.org", "hostname of the wopi server")
	gc.Add("wopi-secret", "bar", "secret to use to connect to the wopi server")

	gc.Add("apps-drawio-url", "https://drawio.web.cern.ch", "The DrawIO URL")

	gc.Add("apps-mail-server", "cernmx.cern.ch:25", "An IMAP mail server where to send mails")
	gc.Add("apps-mail-server-from-address", "cernbox-noreply@cern.ch", "The sender of the mail (FROM header)")

	gc.Add("apps-onlyoffice-document-server", "example.org", "the location of the onlyoffice server")
	gc.Add("apps-gantt-server", "https://gantt-viewer.web.cern.ch", "the location of the gantt server")

	gc.Add("cache-size", 1000000, "cache size for md records")
	gc.Add("cache-eviction", 86400, "cache eviction time in seconds for md records")

	gc.Add("canary-enabled", false, "sets the server as canary")
	gc.Add("canary-cookie-ttl", 10440, "time to live in seconds for the cookie before it expires, default one and a half days")
	gc.Add("canary-force-clean", false, "forces removal of all existing cookies to use old UI")

	gc.Add("dbusername", "foo", "db username")
	gc.Add("dbpassword", "bar", "db password")
	gc.Add("dbhost", "localhost", "dbhost")
	gc.Add("dbport", 3306, "dbport")
	gc.Add("dbname", "cernbox", "dbname")

	gc.Add("base-url", "", "Base url that should be appended to all links (in case cernbox in not in root path)")

	gc.Add("ng-chunk-path", "/var/ng-chunk", "where to store NG dav chunks")

	gc.Add("default-office", "microsoft", "Default Office engine, returned when user hasn't picked one")

	gc.BindFlags()
	gc.ReadConfig()
}

func main() {

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	router := mux.NewRouter()

	canaryOpts := &canary.Options{
		DBUsername: gc.GetString("dbusername"),
		DBPassword: gc.GetString("dbpassword"),
		DBHost:     gc.GetString("dbhost"),
		DBPort:     gc.GetInt("dbport"),
		DBName:     gc.GetString("dbname"),
	}
	cm := canary.New(canaryOpts)

	officeOpts := &office_engine.Options{
		DBUsername:    gc.GetString("dbusername"),
		DBPassword:    gc.GetString("dbpassword"),
		DBHost:        gc.GetString("dbhost"),
		DBPort:        gc.GetInt("dbport"),
		DBName:        gc.GetString("dbname"),
		DefaultOffice: gc.GetString("default-office"),
	}
	oem := office_engine.New(officeOpts)

	otgOpts := &otg.Options{
		DBUsername: gc.GetString("dbusername"),
		DBPassword: gc.GetString("dbpassword"),
		DBHost:     gc.GetString("dbhost"),
		DBPort:     gc.GetInt("dbport"),
		DBName:     gc.GetString("dbname"),
	}
	otge := otg.New(otgOpts)

	opts := &api.Options{
		Router:                   router,
		ThumbnailsFolder:         gc.GetString("thumbnails-folder"),
		TemporaryFolder:          gc.GetString("temporary-folder"),
		ChunksFolder:             gc.GetString("data-chunks-folder"),
		REVAHost:                 gc.GetString("reva-tcp-address"),
		MaxUploadFileSize:        uint64(gc.GetInt("max-upload-file-size")),
		Logger:                   logger,
		CBOXGroupDaemonURI:       gc.GetString("cboxgroupd-http-address"),
		CBOXGroupDaemonSecret:    gc.GetString("cboxgroupd-shared-secret"),
		MaxNumFilesForArchive:    gc.GetInt("archive-max-num-files"),
		MaxSizeForArchive:        gc.GetInt("archive-max-size"),
		MaxViewerFileFize:        gc.GetInt("viewer-max-file-size"),
		OverwriteHost:            gc.GetString("overwrite-host"),
		WopiServer:               gc.GetString("wopi-server"),
		WopiSecret:               gc.GetString("wopi-secret"),
		DrawIOURL:                gc.GetString("apps-drawio-url"),
		CacheSize:                gc.GetInt("cache-size"),
		CacheEviction:            gc.GetInt("cache-eviction"),
		MailServer:               gc.GetString("apps-mail-server"),
		MailServerFromAddress:    gc.GetString("apps-mail-server-from-address"),
		IsCanaryEnabled:          gc.GetBool("canary-enabled"),
		CanaryManager:            cm,
		CanaryForceClean:         gc.GetBool("canary-force-clean"),
		CanaryCookieTTL:          gc.GetInt("canary-cookie-ttl"),
		OfficeEngineManager:      oem,
		OTGManager:               otge,
		Hostname:                 gc.GetString("hostname"),
		OnlyOfficeDocumentServer: gc.GetString("apps-onlyoffice-document-server"),
		GanttServer:              gc.GetString("apps-gantt-server"),
		BaseUrl:                  gc.GetString("base-url"),
		NGChunkPath:              gc.GetString("ng-chunk-path"),
	}

	_, err := api.New(opts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), router)

	err = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		var routeString, path, methods string

		routeString, err = route.GetPathTemplate()
		path, _ = route.GetPathRegexp()
		if v, err := route.GetMethods(); err == nil {
			methods = strings.Join(v, ",")
		}

		logger.Info(methods + " " + routeString + " (regexp: " + path + ")")

		return nil
	})

	logger.Info("server is listening", zap.String("tcp-address", gc.GetString("tcp-address")), zap.Bool("tls-enabled", gc.GetBool("tls-enable")), zap.String("tls-cert", gc.GetString("tls-cert")), zap.String("tls-key", gc.GetString("tls-key")))
	var listenErr error
	if gc.GetBool("tls-enable") {
		listenErr = http.ListenAndServeTLS(gc.GetString("tcp-address"), gc.GetString("tls-cert"), gc.GetString("tls-key"), loggedRouter)
	} else {
		listenErr = http.ListenAndServe(gc.GetString("tcp-address"), loggedRouter)
	}

	if listenErr != nil {
		logger.Error("server exited with error", zap.Error(listenErr))
	} else {
		logger.Info("server exited without error")
	}
}
