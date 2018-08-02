package main

import (
	"net/http"
	"strings"

	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"
	"github.com/cernbox/reva/ocproxy/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

var gc *goconfig.GoConfig

func init() {
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

	gc.Add("data-chunks-folder", "", "folder where to store data chunks before they are commited to REVA.")
	gc.Add("temporary-folder", "", "folder where to store temporary data. Empty means use the OS temporary folder.")
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

	gc.BindFlags()
	gc.ReadConfig()
}

func main() {

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	router := mux.NewRouter()

	opts := &api.Options{
		Router:                router,
		TemporaryFolder:       gc.GetString("temporary-folder"),
		ChunksFolder:          gc.GetString("data-chunks-folder"),
		REVAHost:              gc.GetString("reva-tcp-address"),
		MaxUploadFileSize:     uint64(gc.GetInt("max-upload-file-size")),
		Logger:                logger,
		CBOXGroupDaemonURI:    gc.GetString("cboxgroupd-http-address"),
		CBOXGroupDaemonSecret: gc.GetString("cboxgroupd-shared-secret"),
		MaxNumFilesForArchive: gc.GetInt("archive-max-num-files"),
		MaxSizeForArchive:     gc.GetInt("archive-max-size"),
		MaxViewerFileFize:     gc.GetInt("viewer-max-file-size"),
		OverwriteHost:         gc.GetString("overwrite-host"),
		WopiServer:            gc.GetString("wopi-server"),
		WopiSecret:            gc.GetString("wopi-secret"),
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
