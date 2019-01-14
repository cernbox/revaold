package cmds

import (
	"fmt"
	"net/url"
	"os"

	"github.com/codegangsta/cli"

	"github.com/cernbox/revaold/api"
	"github.com/cernbox/revaold/reva-cli/cmds/authcmd"
	"github.com/cernbox/revaold/reva-cli/cmds/sharecmd"
	"github.com/cernbox/revaold/reva-cli/cmds/storagecmd"
	"github.com/cernbox/revaold/reva-cli/util"

	"golang.org/x/net/context"
)

var StorageCommands = cli.Command{
	Name:    "storage",
	Aliases: []string{"s", "st", "sto"},
	Usage:   "Storage commands",
	Subcommands: []cli.Command{
		storagecmd.InspectCommand,
		storagecmd.MoveCommand,
		storagecmd.DownloadFileCommand,
		storagecmd.UploadFileCommand,
		storagecmd.ListFolderCommand,
		storagecmd.DeleteCommand,

		storagecmd.ListRecycleCommand,
		storagecmd.RestoreRecycleEntryCommand,
		storagecmd.EmptyRecycleCommand,

		storagecmd.ListRevisionsCommand,
		storagecmd.RestoreRevisionCommand,
		storagecmd.DownloadRevisionCommand,
	},
}

var ShareCommands = cli.Command{
	Name:    "sharing",
	Aliases: []string{"sh", "sha"},
	Usage:   "Sharing commands",
	Subcommands: []cli.Command{
		sharecmd.ListFolderSharesCommand,
		sharecmd.CreateFolderShareCommand,
		sharecmd.UpdateFolderShareCommand,
		sharecmd.MountReceivedShareCommand,
		sharecmd.ListReceivedSharesCommand,
		sharecmd.UnmountReceivedShareCommmand,
		sharecmd.RemoveFolderShareCommand,

		sharecmd.InspectPublicLinkCommand,
		sharecmd.ListPublicLinksCommand,
		sharecmd.CreatePublicLinkCommand,
		sharecmd.UpdatePublicLinkCommand,
		sharecmd.RevokePublicLinkCommand,
	},
}

var PreviewCommands = cli.Command{
	Name:        "preview",
	Aliases:     []string{"pre", "prev"},
	Usage:       "Preview commands",
	Subcommands: []cli.Command{},
}

var AuthCommands = cli.Command{
	Name:  "auth",
	Usage: "Auth commands",
	Subcommands: []cli.Command{
		authcmd.ForgePublicLinkTokenCommand,
		authcmd.VerifyTokenCommand,
	},
}

var LoginCommand = cli.Command{
	Name:      "login",
	Usage:     "Login to reva",
	ArgsUsage: "Usage: login <url>",
	Action:    login,
}

func login(c *cli.Context) {
	uri := c.Args().First()
	url, err := url.Parse(uri)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	user := url.User
	if user == nil {
		fmt.Println("Please login with: hugo:secret@myserver:1099")
		os.Exit(1)
	}

	fmt.Println(url.String())
	host := url.Host
	username := url.User.Username()
	password, _ := url.User.Password()

	cfg := &util.Config{Username: username, Password: password, ServerURL: host}
	util.SetConfig(cfg)

	authClient, err := util.GetAuthClient()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	req := &api.ForgeUserTokenReq{ClientId: username, ClientSecret: password}
	tokenRes, err := authClient.ForgeUserToken(context.Background(), req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if tokenRes.Status != api.StatusCode_OK {
		fmt.Println(err)
		os.Exit(1)
	}
	token := tokenRes.Token
	util.SetAccessToken(token)
	fmt.Println("Access token saved in: ", util.AccessTokenFile)
}
