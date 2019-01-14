package authcmd

import (
	"context"
	"fmt"

	"github.com/cernbox/revaold/api"
	"github.com/cernbox/revaold/reva-cli/util"
	"github.com/codegangsta/cli"
)

var ForgePublicLinkTokenCommand = cli.Command{
	Name:      "forge-public-link-token",
	Usage:     "Forges a new access token to access the public link using the storage interface.",
	ArgsUsage: "Usage: forge-public-link-token token  [--password <password>]",
	Action:    forgePublicLinkToken,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "password",
			Usage: "password to access the public link",
		},
	},
}

var VerifyTokenCommand = cli.Command{
	Name:      "verify-token",
	Usage:     "Verifies the retrieved token if any",
	ArgsUsage: "Usage: verify-token [<token>]",
	Action:    verifyToken,
}

func forgePublicLinkToken(c *cli.Context) error {
	if len(c.Args()) < 1 {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	token := c.Args().First()
	password := c.String("password")

	client, err := util.GetAuthClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	ctx := context.Background()
	req := &api.ForgePublicLinkTokenReq{Token: token, Password: password}
	res, err := client.ForgePublicLinkToken(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if res.Status != api.StatusCode_OK {
		return cli.NewExitError(res.Status, 1)
	}
	accessToken := res.Token
	util.SavePublicLinkAccessToken(token, accessToken)
	fmt.Printf("A new access token has been created to acces the public link: %s\n", token)
	return nil
}

func verifyToken(c *cli.Context) {
	fmt.Println("not implemented")
}
