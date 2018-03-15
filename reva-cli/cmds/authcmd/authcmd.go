package authcmd

import (
	"fmt"

	"github.com/codegangsta/cli"
)

var CreateTokenCommand = cli.Command{
	Name:      "create-token",
	Usage:     "Creates a new authentication token",
	ArgsUsage: "Usage: create-token [<username> <password>]",
	Action:    createToken,
}

var VerifyTokenCommand = cli.Command{
	Name:      "verify-token",
	Usage:     "Verifies the retrieved token if any",
	ArgsUsage: "Usage: verify-token [<token>]",
	Action:    verifyToken,
}

func createToken(c *cli.Context) {
	fmt.Println("not implemented")
}

func verifyToken(c *cli.Context) {
	fmt.Println("not implemented")
}
