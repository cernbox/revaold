package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gitlab.com/labkode/reva/api"
	"gitlab.com/labkode/reva/api/authmanager"
	"gitlab.com/labkode/reva/api/eosfs"
	"gitlab.com/labkode/reva/api/eosfs/eosclient"
	"gitlab.com/labkode/reva/api/linkfs"
	"gitlab.com/labkode/reva/api/localfs"
	"gitlab.com/labkode/reva/api/mount"
	"gitlab.com/labkode/reva/api/oclinkmanager"
	"gitlab.com/labkode/reva/api/tokenmanager"
	"gitlab.com/labkode/reva/api/vfs"
	"gitlab.com/labkode/reva/reva-server/svcs/authsvc"
	"gitlab.com/labkode/reva/reva-server/svcs/previewsvc"
	"gitlab.com/labkode/reva/reva-server/svcs/sharesvc"
	"gitlab.com/labkode/reva/reva-server/svcs/storagesvc"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/satori/go.uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	viper.SetDefault("port", 1093)
	viper.SetDefault("signkey", "defaults are evil")
	viper.SetDefault("applog", "stderr")

	viper.SetConfigName("reva")
	viper.AddConfigPath("./")
	viper.AddConfigPath("/etc/reva")

	flag.Int("port", 1093, "Listen port for gRPC connections")
	flag.String("signkey", "defaults are evil", "Key to sign JWT authentication tokens")
	flag.String("applog", "stderr", "File where to log application data")
	flag.String("config", "", "Configuration file to use")

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

	localStorage := localfs.New(&localfs.Options{Namespace: "/home/labkode/go/src/gitlab.com/labkode/reva", Logger: logger})
	localMount := mount.New(localStorage, "/local")

	localTempStorage := localfs.New(&localfs.Options{Namespace: "/tmp", Logger: logger})
	localTempMount := mount.New(localTempStorage, "/tmp")

	// register an eos filesytem
	eosClient, err := eosclient.New(&eosclient.Options{URL: "root://eosexample.cern.ch", EnableLogging: true})
	if err != nil {
		panic(err)
	}

	eosFS := eosfs.New(&eosfs.Options{EosClient: eosClient, Namespace: "/eos/scratch/user/g/gonzalhu", Logger: logger})
	eosMount := mount.New(eosFS, "/home")

	eosLetterFS := eosfs.New(&eosfs.Options{EosClient: eosClient, Namespace: "/eos/scratch/user/", Logger: logger})
	eosLetterMount := mount.New(eosLetterFS, "/user")

	// register a link filesystem
	vFS := vfs.NewVFS(logger)

	linkManager, err := oclinkmanager.New("user", "password", "hostname.cern.ch", 3306, "cernbox9", vFS)
	if err != nil {
		panic(fmt.Errorf("fatal error connecting to db: %s", err))
	}

	authManager := authmanager.New("cerndc.cern.ch", 636, "OU=Users,OU=Organic Units,DC=cern,DC=ch", "(samaccountname=%s)", "binduser", "bindpassword")
	tokenManager := tokenmanager.New("secret")

	linksFS := linkfs.NewLinkFS(vFS, linkManager, logger)
	linkMount := mount.New(linksFS, "/links")

	vFS.AddMount(context.Background(), localMount)
	vFS.AddMount(context.Background(), localTempMount)
	vFS.AddMount(context.Background(), eosMount)
	vFS.AddMount(context.Background(), eosLetterMount)
	vFS.AddMount(context.Background(), linkMount)

	server := grpc.NewServer(
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_opentracing.StreamServerInterceptor(),
			grpc_prometheus.StreamServerInterceptor,
			grpc_zap.StreamServerInterceptor(logger),
			grpc_auth.StreamServerInterceptor(exampleAuthFunc),
			grpc_recovery.StreamServerInterceptor(),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_opentracing.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			grpc_zap.UnaryServerInterceptor(logger),
			grpc_auth.UnaryServerInterceptor(exampleAuthFunc),
			grpc_recovery.UnaryServerInterceptor(),
		)),
	)

	// register prometheus metrics
	grpc_prometheus.Register(server)
	http.Handle("/metrics", promhttp.Handler())

	api.RegisterAuthServer(server, authsvc.New(authManager, tokenManager))
	api.RegisterStorageServer(server, storagesvc.New(vFS))
	api.RegisterShareServer(server, sharesvc.New(linkManager))
	api.RegisterPreviewServer(server, previewsvc.New())

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", viper.GetInt("port")))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	go func() {
		http.ListenAndServe(":1092", nil)
	}()

	log.Fatalf("failed to listen: %v", server.Serve(lis))
}

func exampleAuthFunc(ctx context.Context) (context.Context, error) {
	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, err
	}
	user, err := parseToken(token)
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
	}
	grpc_ctxtags.Extract(ctx).Set("auth.accountid", user.AccountID)
	grpc_ctxtags.Extract(ctx).Set("tid", uuid.NewV4().String())
	newCtx := api.ContextSetUser(ctx, user)
	return newCtx, nil
}

func parseToken(token string) (*api.User, error) {
	// TODO(labkode): parse JWT token
	if token == "" {
		return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: empty token")
	}
	return &api.User{AccountID: "gonzalhu", Groups: []string{"invented-admin-egroup"}}, nil
}
