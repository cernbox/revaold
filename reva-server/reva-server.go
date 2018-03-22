package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/cernbox/reva/api"
	"github.com/cernbox/reva/api/authmanager"
	"github.com/cernbox/reva/api/eosfs"
	"github.com/cernbox/reva/api/eosfs/eosclient"
	"github.com/cernbox/reva/api/homefs"
	"github.com/cernbox/reva/api/linkfs"
	//"github.com/cernbox/reva/api/localfs"
	"github.com/cernbox/reva/api/mount"
	"github.com/cernbox/reva/api/oclinkmanager"
	"github.com/cernbox/reva/api/tokenmanager"
	"github.com/cernbox/reva/api/vfs"
	"github.com/cernbox/reva/reva-server/svcs/authsvc"
	"github.com/cernbox/reva/reva-server/svcs/previewsvc"
	"github.com/cernbox/reva/reva-server/svcs/sharesvc"
	"github.com/cernbox/reva/reva-server/svcs/storagesvc"

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

	flag.String("ldaphostname", "localhost", "LDAP hostname")
	flag.Int("ldapport", 3306, "LDAP port")
	flag.String("ldapbindusername", "admin", "LDAP bind username")
	flag.String("ldapbindpassword", "admin", "LDAP bind password")
	flag.String("ldapfilter", "(samaccountname=%s)", "LDAP filter")
	flag.String("ldapbasedn", "OU=Users,OU=Organic Units,DC=cern,DC=ch", "LDAP base dn")

	flag.String("linkdbhostname", "playground.cern.ch", "Database hostname")
	flag.Int("linkdbport", 3306, "Database port")
	flag.String("linkdbusername", "admin", "Database username")
	flag.String("linkdbpassword", "admin", "Database password")
	flag.String("linkdbname", "cernbox9", "Database name")

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

	/*
		localStorage := localfs.New(&localfs.Options{Namespace: "/home/labkode/go/src/github.com/cernbox/reva", Logger: logger})
		localMount := mount.New(localStorage, "/local")

		localTempStorage := localfs.New(&localfs.Options{Namespace: "/tmp", Logger: logger})
		localTempMount := mount.New(localTempStorage, "/tmp")
	*/

	// register an eos filesytem
	eosClient, err := eosclient.New(&eosclient.Options{URL: "root://eosuat.cern.ch", EnableLogging: true})
	if err != nil {
		panic(err)
	}

	eosFS := eosfs.New(&eosfs.Options{EosClient: eosClient, Namespace: "/eos/scratch/user/", Logger: logger})
	homeFS := homefs.New(eosFS)
	homeMount := mount.New(homeFS, "/home")

	eosLetterFS := eosfs.New(&eosfs.Options{EosClient: eosClient, Namespace: "/eos/", Logger: logger})
	eosLetterMount := mount.New(eosLetterFS, "/eos")

	// register a link filesystem
	vFS := vfs.NewVFS(logger)

	linkManager, err := oclinkmanager.New(viper.GetString("linkdbusername"), viper.GetString("linkdbpassword"), viper.GetString("linkdbhostname"), uint64(viper.GetInt("linkdbport")), viper.GetString("linkdbname"), vFS)
	if err != nil {
		panic(fmt.Errorf("fatal error connecting to db: %s", err))
	}

	authManager := authmanager.New(viper.GetString("ldaphostname"), viper.GetInt("ldapport"), viper.GetString("ldapbasedn"), viper.GetString("ldapfilter"), viper.GetString("ldapbindusername"), viper.GetString("ldapbindpassword"))
	tokenManager := tokenmanager.New("secreto")

	linksFS := linkfs.NewLinkFS(vFS, linkManager, logger)
	linkMount := mount.New(linksFS, "/publiclinks")

	//vFS.AddMount(context.Background(), localMount)
	//vFS.AddMount(context.Background(), localTempMount)
	vFS.AddMount(context.Background(), homeMount)
	vFS.AddMount(context.Background(), eosLetterMount)
	vFS.AddMount(context.Background(), linkMount)

	server := grpc.NewServer(
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_opentracing.StreamServerInterceptor(),
			grpc_prometheus.StreamServerInterceptor,
			grpc_zap.StreamServerInterceptor(logger),
			grpc_auth.StreamServerInterceptor(getAuthFunc(tokenManager)),
			grpc_recovery.StreamServerInterceptor(),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_opentracing.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			grpc_zap.UnaryServerInterceptor(logger),
			grpc_auth.UnaryServerInterceptor(getAuthFunc(tokenManager)),
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

func getAuthFunc(tm api.TokenManager) func(context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		token, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, err
		}

		user, err := tm.VerifyToken(ctx, token)
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
		}

		grpc_ctxtags.Extract(ctx).Set("auth.accountid", user.AccountId)
		grpc_ctxtags.Extract(ctx).Set("tid", uuid.NewV4().String())
		newCtx := api.ContextSetUser(ctx, user)
		return newCtx, nil
	}
}
