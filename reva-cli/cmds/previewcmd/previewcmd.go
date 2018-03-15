package previewcmd

import (
	"fmt"

	"github.com/codegangsta/cli"
)

var DownloadPreviewCommand = cli.Command{
	Name:      "download",
	Usage:     "Download an image preview",
	ArgsUsage: "Usage: download <path>",
	Action:    download,
}

func download(c *cli.Context) {
	fmt.Println("not implemented")
}
