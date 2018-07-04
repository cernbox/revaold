package main

import (
	"net/http"

	"fmt"
	"github.com/gorilla/mux"
	"strings"

	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"

	"github.com/cernbox/reva/ocproxy/api/ocs"
	"github.com/cernbox/reva/ocproxy/api/webdav"
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
	gc.Add("max-upload-file-size", 1024*1024*1024*8, "maximum file size for upload files.")
	gc.Add("jwt-sign-key", "bar", "secret to sign JWT tokens.")
	gc.Add("reva-tcp-address", "localhost:9999", "tcp address of the REVA server.")
	gc.Add("cboxgroupd-http-address", "http://localhost:2002", "http(s) address of the CERNBox Group Daemon (cboxgroupd).")
	gc.Add("cboxgroupd-shared-secret", "bar", "shared secret to connect to the CERNBox Group Daemon (cboxgroupd).")

	gc.BindFlags()
	gc.ReadConfig()
}

func main() {

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	router := mux.NewRouter()

	opts := &webdav.Options{
		Router:            router,
		TemporaryFolder:   gc.GetString("temporary-folder"),
		ChunksFolder:      gc.GetString("data-chunks-folder"),
		REVAHost:          gc.GetString("reva-tcp-address"),
		MaxUploadFileSize: uint64(gc.GetInt("max-upload-file-size")),
		Logger:            logger,
	}

	_, err := webdav.New(opts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	ocsOpts := &ocs.Options{
		Logger:                logger,
		REVAHost:              gc.GetString("reva-tcp-address"),
		CBOXGroupDaemonSecret: gc.GetString("cboxgroupd-http-address"),
		CBOXGroupDaemonURI:    gc.GetString("cboxgroupd-shared-secret"),
		Router:                router,
	}
	_, err = ocs.New(ocsOpts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	err = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err == nil {
			fmt.Println("ROUTE:", pathTemplate)
		}
		pathRegexp, err := route.GetPathRegexp()
		if err == nil {
			fmt.Println("Path regexp:", pathRegexp)
		}
		methods, err := route.GetMethods()
		if err == nil {
			fmt.Println("Methods:", strings.Join(methods, ","))
		}
		fmt.Println()
		return nil
	})

	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), router)

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
