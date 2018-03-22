package main

import (
	"net/http"

	"flag"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"os"
	"strings"

	"github.com/cernbox/reva/oc-proxy/api/webdav"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	viper.SetDefault("port", 1099)
	viper.SetDefault("chunksfolder", "")
	viper.SetDefault("temporaryfolder", "")
	viper.SetDefault("maxuploadfilesize", 1024*1024*1024*8) // 8GiB

	viper.SetDefault("signkey", "defaults are evil")
	viper.SetDefault("applog", "stderr")
	viper.SetDefault("httplog", "stderr")

	viper.SetDefault("revahost", "localhost")
	viper.SetDefault("revaport", 1093)

	viper.SetConfigName("oc-proxy")
	viper.AddConfigPath("./")
	viper.AddConfigPath("/etc/oc-proxy")

	flag.Int("port", 1099, "Listen port for HTTP(S) connections")
	flag.String("signkey", "defaults are evil", "Key to validate JWT authentication tokens")
	flag.String("applog", "stderr", "File where to log application data")
	flag.String("httplog", "stderr", "File where to log http requests")
	flag.String("config", "", "Configuration file to use")
	flag.String("temporaryfolder", "", "Where to storage temporary files")
	flag.String("chunksfolder", "", "Where to store file chunks")
	flag.Int("maxuploadfilesize", 1024*1024*1024*8, "Max upload file size")

	flag.String("revahost", "localhost", "Hostname of the REVA server")
	flag.Int("revaport", 1092, "Port of the REVA server")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
}

func main() {
	if viper.GetString("config") != "" {
		viper.SetConfigFile(viper.GetString("config"))
	}

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error reading config file: %s", err))
	}

	config := zap.NewProductionConfig()
	config.OutputPaths = []string{viper.GetString("applog")}
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	logger, _ := config.Build()

	router := mux.NewRouter()

	opts := &webdav.Options{
		Router:            router,
		TemporaryFolder:   viper.GetString("temporaryfolder"),
		ChunksFolder:      viper.GetString("chunksfolder"),
		REVAHostname:      viper.GetString("revahostname"),
		REVAPort:          viper.GetInt("revaport"),
		MaxUploadFileSize: uint64(viper.GetInt("maxuploadfilesize")),
		Logger:            logger,
	}

	_, err = webdav.New(opts)
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

	out := getHTTPLoggerOut(viper.GetString("httplog"))
	loggedRouter := handlers.LoggingHandler(out, router)

	logger.Info("oc-proxy started", zap.Int("port", viper.GetInt("port")))
	err = http.ListenAndServe(fmt.Sprintf(":%d", viper.GetInt("port")), loggedRouter)
	if err != nil {
		logger.Error("", zap.Error(err))
	}
}

func getHTTPLoggerOut(filename string) *os.File {
	if filename == "stderr" {
		return os.Stderr
	} else if filename == "stdout" {
		return os.Stdout
	} else {
		fd, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		return fd
	}
}
