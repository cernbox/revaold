package main

import (
	"os"

	"github.com/cernbox/revaold/reva-cli/cmds"
	"github.com/codegangsta/cli"
)

func main() {

	app := cli.NewApp()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Hugo GonzÃÂÃÂÃÂÃÂ¡lez Labrador",
			Email: "contact@hugo.labkode.com",
		},
	}
	app.Copyright = "GNU Affero General Public License v3.0"
	app.Name = "reva-cli"
	app.Usage = "Use reva-cli to manage reva services"
	app.Commands = []cli.Command{
		cmds.StorageCommands,
		cmds.AuthCommands,
		cmds.ShareCommands,
		cmds.PreviewCommands,
		cmds.LoginCommand,
	}

	app.Before = func(c *cli.Context) error {
		// TODO(labkode): do something here maybe?
		return nil
	}
	app.Version = "0.1.0"

	app.Run(os.Args)
}
