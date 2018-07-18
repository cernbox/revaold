package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sort"

	"github.com/cernbox/cboxredirectd/api/redismigrator"
	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"

	"github.com/cernbox/reva/api"
	"github.com/cernbox/reva/api/auth_manager_nop"
	"github.com/cernbox/reva/api/mount"
	"github.com/cernbox/reva/api/public_link_manager_owncloud"
	"github.com/cernbox/reva/api/share_manager_owncloud"
	"github.com/cernbox/reva/api/storage_eos"
	"github.com/cernbox/reva/api/storage_homemigration"
	"github.com/cernbox/reva/api/storage_local"
	"github.com/cernbox/reva/api/storage_share"
	"github.com/cernbox/reva/api/storage_usermigration"
	"github.com/cernbox/reva/api/storage_wrapper_home"
	"github.com/cernbox/reva/api/user_manager_cboxgroupd"
	//"github.com/cernbox/reva/api/storage_public_link"
	"github.com/cernbox/reva/api/token_manager_jwt"
	"github.com/cernbox/reva/api/virtual_storage"

	"github.com/cernbox/reva/revad/svcs/authsvc"
	"github.com/cernbox/reva/revad/svcs/previewsvc"
	"github.com/cernbox/reva/revad/svcs/sharesvc"
	"github.com/cernbox/reva/revad/svcs/storagesvc"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/satori/go.uuid"
	//"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func main() {

	gc := goconfig.New()
	gc.SetConfigName("revad")
	gc.AddConfigurationPaths("/etc/revad")
	gc.Add("tcp-address", "localhost:9999", "tcp address to listen for connections.")
	gc.Add("sign-key", "bar", "the key to sign the JWT token.")
	gc.Add("app-log", "stderr", "file to log application information")
	gc.Add("http-log", "stderr", "file to log http log information")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error)")
	gc.Add("tls-cert", "/etc/grid-security/hostcert.pem", "TLS certificate to encrypt connections.")
	gc.Add("tls-key", "/etc/grid-security/hostkey.pem", "TLS private key to encrypt connections.")
	gc.Add("tls-enable", false, "Enable TLS for encrypting connections.")
	gc.Add("mount-table", "/etc/revad/mounts.yaml", "File containing the mounting table.")

	gc.Add("user-manager", "cboxgroupd", "Implementation to use for the user manager")
	gc.Add("user-manager-cboxgroupd-uri", "http://localhost:2002", "URI of the CERNBox Group Daemon")
	gc.Add("user-manager-cboxgroupd-secret", "foo", "Secret to talk to the CERNBox Group Daemon")

	gc.Add("token-manager", "jwt", "Implementation to use for the token manager")
	gc.Add("public-link-manager", "owncloud", "Implementation to use for the public link manager")

	gc.Add("token-manager-jwt-secret", "bar", "Secret to sign JWT tokens.")

	gc.Add("public-link-manager-owncloud-db-username", "foo", "Username to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-password", "bar", "Password to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-hostname", "localhost", "Host where to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-port", 3306, "Port where to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-name", "owncloud", "Name of the owncloud database.")

	gc.Add("redis-tcp-address", "localhost:6379", "redis tcp address")
	gc.Add("redis-read-timeout", 3, "timeout for socket reads. If reached, commands will fail with a timeout instead of blocking. Zero means default.")
	gc.Add("redis-write-timeout", 0, "timeout for socket writes. If reached, commands will fail with a timeout instead of blocking. Zero means redis-read-timeout.")
	gc.Add("redis-dial-timeout", 5, "dial timeout for establishing new connections. Zero means default.")
	gc.Add("redis-idle-check-frequency", 60, "frequency of idle checks. Zero means default. When minus value is set, then idle check is disabled.")
	gc.Add("redis-idle-timeout", 300, "amount of time after which client closes idle connections. Should be less than server's timeout. Zero means default.")
	gc.Add("redis-max-retries", 0, "maximum number of retries before giving up. Zero means not retry failed commands.")
	gc.Add("redis-pool-size", 0, "maximum number of socket connections. Zermo means 10 connections per every CPU as reported by runtime.NumCPU.")
	gc.Add("redis-pool-timeout", 0, "time a client waits for connection if all connections are busy before returning an error. Zero means redis-read-timeout + 1 second.")
	gc.Add("redis-password", "", "the password to authenticate to a protected Redis instance. Empty means no authentication.")

	gc.BindFlags()
	gc.ReadConfig()

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	vs := virtual_storage.NewVFS(logger)
	mountTable := getMountTable(gc)

	userManagerOpt := &user_manager_cboxgroupd.Options{Logger: logger, CBOXGroupDaemonURI: gc.GetString("user-manager-cboxgroupd-uri"), CBOXGroupDaemonSecret: gc.GetString("user-manager-cboxgroupd-secret")}
	userManager := user_manager_cboxgroupd.New(userManagerOpt)
	shareManager, err := share_manager_owncloud.New(gc.GetString("public-link-manager-owncloud-db-username"), gc.GetString("public-link-manager-owncloud-db-password"), gc.GetString("public-link-manager-owncloud-db-hostname"), gc.GetInt("public-link-manager-owncloud-db-port"), gc.GetString("public-link-manager-owncloud-db-name"), vs, userManager)
	publicLinkManager, err := public_link_manager_owncloud.New(gc.GetString("public-link-manager-owncloud-db-username"), gc.GetString("public-link-manager-owncloud-db-password"), gc.GetString("public-link-manager-owncloud-db-hostname"), gc.GetInt("public-link-manager-owncloud-db-port"), gc.GetString("public-link-manager-owncloud-db-name"), vs)

	loadMountTable(logger, vs, mountTable, shareManager)

	/* MIGRATION THINGIES */

	oldHomeMount, err := vs.GetMount("/oldhome")
	if err != nil {
		panic(err)
	}

	newHomeMap := map[string]api.Storage{}
	for _, l := range "abcdefghilmnopqrstuvwxyz" {
		letter := string(l)
		m, err := vs.GetMount(fmt.Sprintf("/eoshome-%s", letter))
		if err != nil {
			panic(err)
		}
		newHomeMap[letter] = m.GetStorage()
	}

	migratorOpts := &redismigrator.Options{
		Address:            gc.GetString("redis-tcp-address"),
		DialTimeout:        gc.GetInt("redis-dial-timeout"),
		IdleCheckFrequency: gc.GetInt("redis-idle-check-frequency"),
		IdleTimeout:        gc.GetInt("redis-idle-timeout"),
		Logger:             logger,
		MaxRetries:         gc.GetInt("redis-max-retries"),
		PoolSize:           gc.GetInt("redis-pool-size"),
		PoolTimeout:        gc.GetInt("redis-pool-timeout"),
		ReadTimeout:        gc.GetInt("redis-read-timeout"),
		WriteTimeout:       gc.GetInt("redis-write-timeout"),
		Password:           gc.GetString("redis-password"),
	}

	migrator, err := redismigrator.New(migratorOpts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	opts := &storage_homemigration.Options{
		OldHome:    oldHomeMount.GetStorage(),
		Logger:     logger,
		NewHomeMap: newHomeMap,
		Migrator:   migrator,
	}

	storage, err := storage_homemigration.New(opts)
	if err != nil {
		panic(err)
	}

	oldUserMount, err := vs.GetMount("/old/user")
	if err != nil {
		panic(err)
	}

	newUserMap := map[string]api.Storage{}
	//for _, l := range "abcdefghilmnopqrstuvwxyz" {
	for _, l := range "l" {
		letter := string(l)
		m, err := vs.GetMount(fmt.Sprintf("/new/user/%s", letter))
		if err != nil {
			panic(err)
		}
		newUserMap[letter] = m.GetStorage()
	}

	opts2 := &storage_usermigration.Options{
		OldUser:    oldUserMount.GetStorage(),
		Logger:     logger,
		NewUserMap: newUserMap,
		Migrator:   migrator,
	}

	userStorage, err := storage_usermigration.New(opts2)
	if err != nil {
		panic(err)
	}

	homeMount := mount.New("home", "/home", &api.MountOptions{}, storage)
	userMount := mount.New("user", "/eos/user", &api.MountOptions{}, userStorage)
	vs.AddMount(context.Background(), homeMount)
	vs.AddMount(context.Background(), userMount)
	/* END Migration stuff */

	tokenManager := token_manager_jwt.New(gc.GetString("token-manager-jwt-secret"))
	authManager := auth_manager_nop.New()
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

	api.RegisterAuthServer(server, authsvc.New(authManager, tokenManager, publicLinkManager))
	api.RegisterStorageServer(server, storagesvc.New(vs))
	api.RegisterShareServer(server, sharesvc.New(publicLinkManager, shareManager))
	api.RegisterPreviewServer(server, previewsvc.New())

	logger.Info("listening for grpc connecitons on: " + gc.GetString("tcp-address"))
	lis, err := net.Listen("tcp", gc.GetString("tcp-address"))
	if err != nil {
		logger.Fatal("failed to listen", zap.Error(err))
	}
	go func() {
		http.ListenAndServe(":1092", nil)
	}()

	log.Fatalf("failed to listen: %v", server.Serve(lis))
}

func getMountTable(gc *goconfig.GoConfig) *api.MountTable {
	mountFile := gc.GetString("mount-table")
	contents, err := ioutil.ReadFile(mountFile)
	if err != nil {
		panic(err)
	}
	mt := &api.MountTable{}
	err = json.Unmarshal(contents, mt)
	if err != nil {
		panic(err)
	}
	return mt
}

func applyStorageWrappers(s api.Storage, storageWrappers []*api.StorageWrapper) (api.Storage, error) {
	// sort list of storage wrappers by priority
	sort.Slice(storageWrappers, func(i, j int) bool {
		return storageWrappers[i].Priority < storageWrappers[j].Priority
	})

	for _, sw := range storageWrappers {
		switch sw.Name {
		case "home":
			homeWrapper := storage_wrapper_home.New(s)
			s = homeWrapper
		}

	}

	return s, nil
}

func loadMountTable(logger *zap.Logger, vs api.VirtualStorage, mt *api.MountTable, sm api.ShareManager) error {
	mounts := []api.Mount{}
	for _, mte := range mt.Mounts {
		storageDriver := mte.StorageDriver
		switch storageDriver {
		case "local":
			bytes, err := json.Marshal(mte.StorageOptions)
			if err != nil {
				panic(err)
			}
			opts := &storage_local.Options{}
			err = json.Unmarshal(bytes, opts)
			if err != nil {
				panic(err)
			}
			storage := storage_local.New(opts)
			storage, err = applyStorageWrappers(storage, mte.StorageWrappers)
			if err != nil {
				panic(err)
			}

			mount := mount.New(mte.MountID, mte.MountPoint, mte.MountOptions, storage)
			mounts = append(mounts, mount)
		case "eos":
			bytes, err := json.Marshal(mte.StorageOptions)
			if err != nil {
				panic(err)
			}
			opts := &storage_eos.Options{}
			err = json.Unmarshal(bytes, opts)
			if err != nil {
				panic(err)
			}
			storage, err := storage_eos.New(opts)
			if err != nil {
				panic(err)
			}

			storage, err = applyStorageWrappers(storage, mte.StorageWrappers)
			if err != nil {
				panic(err)
			}

			mount := mount.New(mte.MountID, mte.MountPoint, mte.MountOptions, storage)
			mounts = append(mounts, mount)
		case "share":
			bytes, err := json.Marshal(mte.StorageOptions)
			if err != nil {
				panic(err)
			}
			opts := &storage_share.Options{}
			err = json.Unmarshal(bytes, opts)
			if err != nil {
				panic(err)
			}
			storage := storage_share.New(opts, vs, sm, logger)

			storage, err = applyStorageWrappers(storage, mte.StorageWrappers)
			if err != nil {
				panic(err)
			}

			mount := mount.New(mte.MountID, mte.MountPoint, mte.MountOptions, storage)
			mounts = append(mounts, mount)

		}
	}

	// register mounts into the virtual storage
	for _, m := range mounts {
		fmt.Printf("%+v", m)
		vs.AddMount(context.Background(), m)
	}
	return nil
	/*
		localStorage := storage_local.New(&storage_local.Options{Namespace: "/home/labkode/go/src/github.com/cernbox/reva", Logger: logger})

		localMount := mount.New(localStorage, "/local")

		localTempStorage := storage_local.New(&storage_local.Options{Namespace: "/tmp", Logger: logger})
		localTempMount := mount.New(localTempStorage, "/tmp")

		eosStorage, err := storage_eos.New(&storage_eos.Options{
			Namespace:     "/eos/scratch/user/",
			Logger:        logger,
			URL:           "root://uat.cern.ch",
			EnableLogging: true,
		})
		if err != nil {
			panic(err)
		}

		homeStorage := storage_home.New(eosStorage)
		homeMount := mount.New(homeStorage, "/home")

		eosLetterStorage, err := storage_eos.New(&storage_eos.Options{
			Namespace:     "/eos/scratch/user/",
			Logger:        logger,
			URL:           "root://uat.cern.ch",
			EnableLogging: true,
		})
		if err != nil {
			panic(err)
		}

		eosLetterMount := mount.New(eosLetterStorage, "/eos")

		// register a link filesystem
		vFS := virtual_storage.NewVFS(logger)

		if err != nil {
			panic(fmt.Errorf("fatal error connecting to db: %s", err))
		}

		tokenManager := token_manager_jwt.New("secreto")

		linksFS := storage_public_link.NewLinkFS(vFS, linkManager, logger)
		linkMount := mount.New(linksFS, "/publiclinks")

		vFS.AddMount(context.Background(), localMount)
		vFS.AddMount(context.Background(), localTempMount)
		vFS.AddMount(context.Background(), homeMount)
		vFS.AddMount(context.Background(), eosLetterMount)
		vFS.AddMount(context.Background(), linkMount)
	*/
}

func getAuthFunc(tm api.TokenManager) func(context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {

		// check for user token
		token, err := grpc_auth.AuthFromMD(ctx, "user-bearer")
		if err == nil {
			user, err := tm.DismantleUserToken(ctx, token)
			if err != nil {
				return nil, grpc.Errorf(codes.Unauthenticated, "invalid user auth token: %v", err)
			}

			grpc_ctxtags.Extract(ctx).Set("auth.accountid", user.AccountId)
			uuid, _ := uuid.NewV4()
			tid := uuid.String()
			grpc_ctxtags.Extract(ctx).Set("tid", tid)
			newCtx := api.ContextSetUser(ctx, user)
			return newCtx, nil

		}

		// check for public link token
		token, err = grpc_auth.AuthFromMD(ctx, "pl-bearer")
		if err == nil {
			pl, err := tm.DismantlePublicLinkToken(ctx, token)
			if err != nil {
				return nil, grpc.Errorf(codes.Unauthenticated, "invalid pl auth token: %v", err)
			}

			grpc_ctxtags.Extract(ctx).Set("auth.accountid", pl.Token)
			uuid, _ := uuid.NewV4()
			tid := uuid.String()
			grpc_ctxtags.Extract(ctx).Set("tid", tid)
			newCtx := api.ContextSetPublicLink(ctx, pl)
			return newCtx, nil

		}

		return nil, err
	}
}
