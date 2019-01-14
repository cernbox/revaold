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

	"github.com/cernbox/revaold/api"
	"github.com/cernbox/revaold/api/auth_manager_impersonate"
	"github.com/cernbox/revaold/api/auth_manager_ldap"
	"github.com/cernbox/revaold/api/mount"
	"github.com/cernbox/revaold/api/project_manager_db"
	"github.com/cernbox/revaold/api/public_link_manager_owncloud"
	"github.com/cernbox/revaold/api/share_manager_owncloud"
	"github.com/cernbox/revaold/api/storage_all_projects"
	"github.com/cernbox/revaold/api/storage_eos"
	"github.com/cernbox/revaold/api/storage_homemigration"
	"github.com/cernbox/revaold/api/storage_local"
	"github.com/cernbox/revaold/api/storage_public_link"
	"github.com/cernbox/revaold/api/storage_share"
	"github.com/cernbox/revaold/api/storage_usermigration"
	"github.com/cernbox/revaold/api/storage_wrapper_home"
	"github.com/cernbox/revaold/api/tag_manager_db"
	"github.com/cernbox/revaold/api/token_manager_jwt"
	"github.com/cernbox/revaold/api/user_manager_cboxgroupd"
	"github.com/cernbox/revaold/api/virtual_storage"
	"github.com/cernbox/revaold/revad/svcs/authsvc"
	"github.com/cernbox/revaold/revad/svcs/previewsvc"
	"github.com/cernbox/revaold/revad/svcs/sharesvc"
	"github.com/cernbox/revaold/revad/svcs/storagesvc"
	"github.com/cernbox/revaold/revad/svcs/taggersvc"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/grpc-ecosystem/go-grpc-prometheus"

	"github.com/gofrs/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.uber.org/zap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var gc *goconfig.GoConfig
var logger *zap.Logger
var vs api.VirtualStorage
var tokenManager api.TokenManager
var authManager api.AuthManager
var publicLinkManager api.PublicLinkManager
var shareManager api.ShareManager
var userManager api.UserManager
var projectManager api.ProjectManager
var tagManager api.TagManager

func main() {

	mountTable := getMountTable(gc)

	loadMountTable(mountTable)

	// TODO(labkode): remove this hack for the migration scenario
	applyMigrationLogic()

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
	api.RegisterStorageServer(server, storagesvc.New(vs, gc.GetString("svc-storage-tx-temporary-folder")))
	api.RegisterShareServer(server, sharesvc.New(publicLinkManager, shareManager))
	api.RegisterPreviewServer(server, previewsvc.New())
	api.RegisterTaggerServer(server, taggersvc.New(tagManager))

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

func loadMountTable(mt *api.MountTable) error {
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
			opts.Logger = logger
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
			storage := storage_share.New(opts, vs, shareManager, logger)

			storage, err = applyStorageWrappers(storage, mte.StorageWrappers)
			if err != nil {
				panic(err)
			}

			mount := mount.New(mte.MountID, mte.MountPoint, mte.MountOptions, storage)
			mounts = append(mounts, mount)

		case "public_link":
			bytes, err := json.Marshal(mte.StorageOptions)
			if err != nil {
				panic(err)
			}
			opts := &storage_public_link.Options{}
			err = json.Unmarshal(bytes, opts)
			if err != nil {
				panic(err)
			}
			storage := storage_public_link.New(opts, vs, publicLinkManager, logger)

			storage, err = applyStorageWrappers(storage, mte.StorageWrappers)
			if err != nil {
				panic(err)
			}

			mount := mount.New(mte.MountID, mte.MountPoint, mte.MountOptions, storage)
			mounts = append(mounts, mount)
		case "all_projects":
			bytes, err := json.Marshal(mte.StorageOptions)
			if err != nil {
				panic(err)
			}
			opts := &storage_all_projects.Options{}
			err = json.Unmarshal(bytes, opts)
			if err != nil {
				panic(err)
			}
			storage := storage_all_projects.New(opts, vs, userManager, projectManager, logger)

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
			if err == nil {
				grpc_ctxtags.Extract(ctx).Set("auth.accountid", user.AccountId)
				uuid := uuid.Must(uuid.NewV4())
				tid := uuid.String()
				grpc_ctxtags.Extract(ctx).Set("tid", tid)
				newCtx := api.ContextSetUser(ctx, user)
				return newCtx, nil
			}
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

			// we set the user context as well from the owner of the link
			newCtx = api.ContextSetUser(newCtx, &api.User{AccountId: pl.OwnerId, Groups: []string{}})
			return newCtx, nil

		}

		return nil, err
	}
}

func init() {
	gc = goconfig.New()
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

	gc.Add("auth-manager", "impersonate", "Implementation to use for the auth manager")
	gc.Add("auth-manager-ldap-hostname", "localhost", "Hostname for the LDAP server")
	gc.Add("auth-manager-ldap-port", 389, "Port for the LDAP server")
	gc.Add("auth-manager-ldap-basedn", "OU=Users,OU=Organic Units,DC=cern,DC=ch", "Base DN for LDAP queries.")
	gc.Add("auth-manager-ldap-filter", "(samaccountname=%s)", "Filter for LDAP queries.")
	gc.Add("auth-manager-ldap-bind-username", "DN=foo,OU=Users,OU=Organic Units,DC=cern,DC=ch", "Username to bind to LDAP.")
	gc.Add("auth-manager-ldap-bind-password", "bar", "Password to bind to LDAP.")

	gc.Add("user-manager", "cboxgroupd", "Implementation to use for the user manager")
	gc.Add("user-manager-cboxgroupd-uri", "http://localhost:2002", "URI of the CERNBox Group Daemon")
	gc.Add("user-manager-cboxgroupd-secret", "bar", "Secret to talk to the CERNBox Group Daemon")

	gc.Add("project-manager", "db", "Implementation to use for the project manager")
	gc.Add("project-manager-db-username", "foo", "Username to access the database.")
	gc.Add("project-manager-db-password", "bar", "Password to access the database.")
	gc.Add("project-manager-db-hostname", "localhost", "Host where to access the database.")
	gc.Add("project-manager-db-port", 3306, "Port where to access the database.")
	gc.Add("project-manager-db-name", "", "Name of the database.")

	gc.Add("token-manager", "jwt", "Implementation to use for the token manager")
	gc.Add("token-manager-jwt-secret", "bar", "Secret to sign JWT tokens.")

	gc.Add("public-link-manager", "owncloud", "Implementation to use for the public link manager")
	gc.Add("public-link-manager-owncloud-db-username", "foo", "Username to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-password", "bar", "Password to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-hostname", "localhost", "Host where to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-port", 3306, "Port where to access the owncloud database.")
	gc.Add("public-link-manager-owncloud-db-name", "owncloud", "Name of the owncloud database.")
	gc.Add("public-link-manager-owncloud-cache-size", 1000000, "cache size for metadata operations of public link to files.")
	gc.Add("public-link-manager-owncloud-cache-eviction", 86400, "cache eviction in seconds to purge elements.")

	gc.Add("tag-manager", "db", "Implementation to use for the tag manager")
	gc.Add("tag-manager-db-username", "foo", "Username to access the  database.")
	gc.Add("tag-manager-db-password", "bar", "Password to access the  database.")
	gc.Add("tag-manager-db-hostname", "localhost", "Host where to access the  database.")
	gc.Add("tag-manager-db-port", 3306, "Port where to access the  database.")
	gc.Add("tag-manager-db-name", "", "Name of the  database.")

	gc.Add("mig-redis-tcp-address", "localhost:6379", "redis tcp address")
	gc.Add("mig-redis-read-timeout", 3, "timeout for socket reads. If reached, commands will fail with a timeout instead of blocking. Zero means default.")
	gc.Add("mig-redis-write-timeout", 0, "timeout for socket writes. If reached, commands will fail with a timeout instead of blocking. Zero means mig-redis-read-timeout.")
	gc.Add("mig-redis-dial-timeout", 5, "dial timeout for establishing new connections. Zero means default.")
	gc.Add("mig-redis-idle-check-frequency", 60, "frequency of idle checks. Zero means default. When minus value is set, then idle check is disabled.")
	gc.Add("mig-redis-idle-timeout", 300, "amount of time after which client closes idle connections. Should be less than server's timeout. Zero means default.")
	gc.Add("mig-redis-max-retries", 0, "maximum number of retries before giving up. Zero means not retry failed commands.")
	gc.Add("mig-redis-pool-size", 0, "maximum number of socket connections. Zermo means 10 connections per every CPU as reported by runtime.NumCPU.")
	gc.Add("mig-redis-pool-timeout", 0, "time a client waits for connection if all connections are busy before returning an error. Zero means mig-redis-read-timeout + 1 second.")
	gc.Add("mig-redis-password", "", "the password to authenticate to a protected Redis instance. Empty means no authentication.")

	gc.Add("mig-eosuser-homedir-script", "/root/eosuser-homedir-creation.sh", "script to create home directory on EOSUSER")
	gc.Add("mig-eosuser-homedir-script-enabled", false, "if set enables creation of home dirs in EOSUSER")

	gc.Add("mig-eoshome-homedir-script", "/root/eoshome-homedir-creation.sh", "script to create home directory on EOSHOME")
	gc.Add("mig-eoshome-homedir-script-enabled", false, "if set enables creation of home dirs in EOSHOME")

	gc.Add("svc-storage-tx-temporary-folder", "", "temporary folder to create and assemble write tx, if default, assumes os.Tempdir")

	gc.BindFlags()
	gc.ReadConfig()

	logger = gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	vs = virtual_storage.NewVFS(logger)
	userManager = getUserManager()
	shareManager = getShareManager()
	publicLinkManager = getPublicLinkManager()
	projectManager = getProjectManager()
	tokenManager = getTokenManager()
	authManager = getAuthManager()
	tagManager = getTagManager()
}

func getUserManager() api.UserManager {
	userManagerOpt := &user_manager_cboxgroupd.Options{Logger: logger, CBOXGroupDaemonURI: gc.GetString("user-manager-cboxgroupd-uri"), CBOXGroupDaemonSecret: gc.GetString("user-manager-cboxgroupd-secret")}
	userManager := user_manager_cboxgroupd.New(userManagerOpt)
	return userManager
}
func getShareManager() api.ShareManager {
	shareManager, err := share_manager_owncloud.New(gc.GetString("public-link-manager-owncloud-db-username"), gc.GetString("public-link-manager-owncloud-db-password"), gc.GetString("public-link-manager-owncloud-db-hostname"), gc.GetInt("public-link-manager-owncloud-db-port"), gc.GetString("public-link-manager-owncloud-db-name"), vs, userManager)
	if err != nil {
		panic(err)
	}
	return shareManager
}
func getPublicLinkManager() api.PublicLinkManager {
	publicLinkManager, err := public_link_manager_owncloud.New(gc.GetString("public-link-manager-owncloud-db-username"), gc.GetString("public-link-manager-owncloud-db-password"), gc.GetString("public-link-manager-owncloud-db-hostname"), gc.GetInt("public-link-manager-owncloud-db-port"), gc.GetString("public-link-manager-owncloud-db-name"), gc.GetInt("public-link-manager-owncloud-cache-size"), gc.GetInt("public-link-manager-owncloud-cache-eviction"), vs)
	if err != nil {
		panic(err)
	}
	return publicLinkManager
}
func getProjectManager() api.ProjectManager {
	projectManager := project_manager_db.New(gc.GetString("project-manager-db-username"), gc.GetString("project-manager-db-password"), gc.GetString("project-manager-db-hostname"), gc.GetInt("project-manager-db-port"), gc.GetString("project-manager-db-name"), vs)
	return projectManager
}

func getTokenManager() api.TokenManager {
	tokenManager := token_manager_jwt.New(gc.GetString("token-manager-jwt-secret"))
	return tokenManager
}
func getAuthManager() api.AuthManager {
	driver := gc.GetString("auth-manager")
	switch driver {
	case "impersonate":
		return auth_manager_impersonate.New()
	case "ldap":
		hostname := gc.GetString("auth-manager-ldap-hostname")
		port := gc.GetInt("auth-manager-ldap-port")
		baseDN := gc.GetString("auth-manager-ldap-basedn")
		filter := gc.GetString("auth-manager-ldap-filter")
		bindUsername := gc.GetString("auth-manager-ldap-bind-username")
		bindPassword := gc.GetString("auth-manager-ldap-bind-password")
		return auth_manager_ldap.New(hostname, port, baseDN, filter, bindUsername, bindPassword)
	default:
		panic("auth manager driver not found: " + driver)
	}
}
func getTagManager() api.TagManager {
	tagManager := tag_manager_db.New(gc.GetString("tag-manager-db-username"), gc.GetString("tag-manager-db-password"), gc.GetString("tag-manager-db-hostname"), gc.GetInt("tag-manager-db-port"), gc.GetString("tag-manager-db-name"), vs)
	return tagManager
}

func applyMigrationLogic() {
	oldHomeMount, err := vs.GetMount("/oldhome")
	if err != nil {
		panic(err)
	}

	newHomeMap := map[string]api.Storage{}
	for _, l := range "abcdefghijklmnopqrstuvwxyz" {
		letter := string(l)
		m, err := vs.GetMount(fmt.Sprintf("/eoshome-%s", letter))
		if err != nil {
			panic(err)
		}
		newHomeMap[letter] = m.GetStorage()
	}

	migratorOpts := &redismigrator.Options{
		Address:            gc.GetString("mig-redis-tcp-address"),
		DialTimeout:        gc.GetInt("mig-redis-dial-timeout"),
		IdleCheckFrequency: gc.GetInt("mig-redis-idle-check-frequency"),
		IdleTimeout:        gc.GetInt("mig-redis-idle-timeout"),
		Logger:             logger,
		MaxRetries:         gc.GetInt("mig-redis-max-retries"),
		PoolSize:           gc.GetInt("mig-redis-pool-size"),
		PoolTimeout:        gc.GetInt("mig-redis-pool-timeout"),
		ReadTimeout:        gc.GetInt("mig-redis-read-timeout"),
		WriteTimeout:       gc.GetInt("mig-redis-write-timeout"),
		Password:           gc.GetString("mig-redis-password"),
	}

	migrator, err := redismigrator.New(migratorOpts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	opts := &storage_homemigration.Options{
		OldHome:             oldHomeMount.GetStorage(),
		Logger:              logger,
		NewHomeMap:          newHomeMap,
		Migrator:            migrator,
		EosHomeEnableScript: gc.GetBool("mig-eoshome-homedir-script-enabled"),
		EosUserEnableScript: gc.GetBool("mig-eosuser-homedir-script-enabled"),
		EosUserScript:       gc.GetString("mig-eosuser-homedir-script"),
		EosHomeScript:       gc.GetString("mig-eoshome-homedir-script"),
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
	for _, l := range "abcdefghijklmnopqrstuvwxyz" {
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
}
