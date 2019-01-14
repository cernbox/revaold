package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/cernbox/revaold/api"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	DefaultServerHost = "localhost"
	DefaultServerPort = 1094
)

var ConfigDir string
var ConfigFile string
var LogFile string
var AccessTokenFile string

type Config struct {
	Username  string
	Password  string
	ServerURL string
}

func init() {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	home := u.HomeDir
	ConfigDir = path.Join(home, ".reva-cli")
	ConfigFile = path.Join(ConfigDir, "config")
	LogFile = path.Join(ConfigDir, "log")
	AccessTokenFile = path.Join(ConfigDir, "access-token")

	// check if ConfigDir exists or not
	if _, err := os.Stat(ConfigDir); os.IsNotExist(err) {
		os.Mkdir(ConfigDir, 0700)
	}
}

func GetConfig() *Config {
	c := &Config{}
	data, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		return c
	}
	if err := json.Unmarshal(data, c); err != nil {
		return c
	}
	return c
}

func SetConfig(cfg *Config) {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	ioutil.WriteFile(ConfigFile, data, 0600)
}

func GetAccessToken() string {
	data, err := ioutil.ReadFile(AccessTokenFile)
	if err != nil {
		return ""
	}
	return string(data)
}

func SetAccessToken(token string) {
	if err := ioutil.WriteFile(AccessTokenFile, []byte(token), 0600); err != nil {
		log.Fatalln(err)
	}
}

func SavePublicLinkAccessToken(token, accessToken string) {
	p := path.Join(ConfigDir, fmt.Sprintf("public-link-access-token-for-%s", token))
	if err := ioutil.WriteFile(p, []byte(accessToken), 0600); err != nil {
		log.Fatalln(err)
	}
}

func LoadPublicLinkAccessToken(token string) (string, error) {
	p := path.Join(ConfigDir, fmt.Sprintf("public-link-access-token-for-%s", token))
	data, err := ioutil.ReadFile(p)
	if err != nil {
		return "", err
	}
	return string(data), nil

}

func getConn() (*grpc.ClientConn, error) {
	cfg := GetConfig()
	return grpc.Dial(cfg.ServerURL, grpc.WithInsecure())
}

func GetAuthClient() (api.AuthClient, error) {
	conn, err := getConn()
	if err != nil {
		return nil, err
	}
	return api.NewAuthClient(conn), nil
}

func GetStorageClient() (api.StorageClient, error) {
	conn, err := getConn()
	if err != nil {
		return nil, err
	}
	return api.NewStorageClient(conn), nil
}

func GetSharingClient() (api.ShareClient, error) {
	conn, err := getConn()
	if err != nil {
		return nil, err
	}
	return api.NewShareClient(conn), nil
}

func GetPreviewClient() (api.PreviewClient, error) {
	conn, err := getConn()
	if err != nil {
		return nil, err
	}
	return api.NewPreviewClient(conn), nil
}

func GetContextWithAuth() context.Context {
	token := GetAccessToken()
	header := metadata.New(map[string]string{"authorization": "user-bearer " + token})
	return metadata.NewOutgoingContext(context.Background(), header)
}

func GetContextWithAllAuths(path string) context.Context {
	if strings.HasPrefix(path, "/public-links/") {
		plToken := strings.Split(strings.TrimPrefix(path, "/public-links/"), "/")[0]
		fmt.Println(plToken)
		plAccessToken, err := LoadPublicLinkAccessToken(plToken)
		if err != nil {
			fmt.Println("error: cannot load public link access token: " + err.Error())
		}
		header := metadata.New(map[string]string{"authorization": "pl-bearer " + plAccessToken})
		return metadata.NewOutgoingContext(context.Background(), header)
	}

	token := GetAccessToken()
	header := metadata.New(map[string]string{"authorization": "user-bearer " + token})
	return metadata.NewOutgoingContext(context.Background(), header)
}
