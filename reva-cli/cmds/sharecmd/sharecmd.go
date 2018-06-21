package sharecmd

import (
	"fmt"
	"io"
	"time"

	"github.com/cernbox/reva/api"
	"github.com/cernbox/reva/reva-cli/util"

	"github.com/codegangsta/cli"
	"github.com/ryanuber/columnize"
)

var CreateFolderShareCommand = cli.Command{
	Name:      "folder-share-create",
	Usage:     "Creates a folder share",
	ArgsUsage: "Usage: folder-share-create <path> <recipient> <read-only>",
	Action:    createFolderShare,
}

var ListFolderSharesCommand = cli.Command{
	Name:      "folder-share-list",
	Usage:     "List folder shares",
	ArgsUsage: "Usage: folder-share-list [path]",
	Action:    listFolderShares,
}

var RemoveFolderShareCommand = cli.Command{
	Name:      "folder-share-remove",
	Usage:     "Delete a folder share",
	ArgsUsage: "Usage: folder-share-remove <share-id>",
	Action:    removeFolderShare,
}

var UpdateFolderShareCommand = cli.Command{
	Name:      "folder-share-update",
	Usage:     "Update a folder share",
	ArgsUsage: "Usage: folder-share-update <share-id> <read-only>",
	Action:    updateFolderShare,
}

var ListReceivedSharesCommand = cli.Command{
	Name:      "received-share-list",
	Usage:     "List of received folder shares",
	ArgsUsage: "Usage: received-shares-list",
	Action:    listReceivedShares,
}

var MountReceivedShareCommand = cli.Command{
	Name:      "received-share-mount",
	Usage:     "Marks a received share to be mounted",
	ArgsUsage: "Usage: received-share-mount <share-id>",
	Action:    mountReceivedShare,
}

var UnmountReceivedShareCommmand = cli.Command{
	Name:      "received-share-unmount",
	Usage:     "Marks a received share to be unmounted",
	ArgsUsage: "Usage: received-share-unmount <share-id>",
	Action:    unmountReceivedShare,
}

var CreatePublicLinkCommand = cli.Command{
	Name:      "public-link-create",
	Usage:     "Creates a public link",
	ArgsUsage: "<path>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "password",
			Usage: "password to protected the access to the link",
		},
		cli.BoolFlag{
			Name:  "read-write",
			Usage: "Sets the link contents to read-write to people can add/delete files",
		},
		cli.StringFlag{
			Name:  "expiration",
			Usage: "expiration time for the link, like 2018-02-28:12:45:00",
		},
	},
	Action: createPublicLink,
}

var RevokePublicLinkCommand = cli.Command{
	Name:      "public-link-revoke",
	Usage:     "Revokes a public link",
	ArgsUsage: "Usage: public-link-revoke <token>",
	Action:    revokePublicLink,
}

var InspectPublicLinkCommand = cli.Command{
	Name:      "public-link-inspect",
	Usage:     "Inspects a public link",
	ArgsUsage: "Usage: public-link-inspect <token>",
	Action:    inspectPublicLink,
}

var ListPublicLinksCommand = cli.Command{
	Name:      "public-link-list",
	Usage:     "List all public links",
	ArgsUsage: "Usage: public-link-list",
	Action:    listPublicLinks,
}

var UpdatePublicLinkCommand = cli.Command{
	Name:      "public-link-update",
	Usage:     "Updates a public link",
	ArgsUsage: "Usage: public-link-update <token>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "password",
			Usage: "password to protected the access to the link",
		},
		cli.BoolFlag{
			Name:  "read-only",
			Usage: "set link to read-only",
		},
		cli.StringFlag{
			Name:  "expiration",
			Usage: "expiration time for the link, like 2018-02-28:12:45:00",
		},
		cli.BoolFlag{
			Name:  "set-expiration",
			Usage: "set expiration field to the value from --expiration flag",
		},
		cli.BoolFlag{
			Name:  "set-password",
			Usage: "set password field to the value from --password flag",
		},
		cli.BoolFlag{
			Name:  "set-read-only",
			Usage: "set read-only field to the value from --read-only flag",
		},
	},
	Action: updatePublicLink,
}

func inspectPublicLink(c *cli.Context) error {
	id := c.Args().First()
	if id == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	req := &api.ShareIDReq{Id: id}
	ctx := util.GetContextWithAuth()
	linkRes, err := client.InspectPublicLink(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if linkRes.Status != api.StatusCode_OK {
		return cli.NewExitError(linkRes.Status, 1)
	}
	link := linkRes.PublicLink
	modified := time.Unix(int64(link.Mtime), 0).Format(time.RFC3339)
	expires := time.Unix(int64(link.Expires), 0).Format(time.RFC3339)
	fmt.Fprintf(c.App.Writer, "Token: %s\nProtected: %t\nReadOnly: %t\nModify: %s Timestamp: %d\nExpires: %s Timestamp: %d\nPath: %s\n", link.Token, link.Protected, link.ReadOnly, modified, link.Mtime, expires, link.Expires, link.Path)
	return nil
}

func createPublicLink(c *cli.Context) error {
	path := c.Args().First()
	if path == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	req := &api.NewLinkReq{
		Password: c.String("password"),
		ReadOnly: !c.Bool("read-write"),
		Path:     path,
	}

	if c.String("expiration") != "" {
		t, err := time.Parse("2006-01-02 03:04:05", c.String("expiration"))
		if err != nil {
			return cli.NewExitError(err, 1)
		}
		req.Expires = uint64(t.Unix())
	}

	ctx := util.GetContextWithAuth()
	linkRes, err := client.CreatePublicLink(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if linkRes.Status != api.StatusCode_OK {
		return cli.NewExitError(linkRes.Status, 1)
	}
	link := linkRes.PublicLink

	modified := time.Unix(int64(link.Mtime), 0).Format(time.RFC3339)
	expires := time.Unix(int64(link.Expires), 0).Format(time.RFC3339)
	fmt.Fprintf(c.App.Writer, "Token: %s\nProtected: %t\nReadOnly: %t\nModify: %s Timestamp: %d\nExpires: %s Timestamp: %d\nPath: %s\n", link.Token, link.Protected, link.ReadOnly, modified, link.Mtime, expires, link.Expires, link.Path)
	return nil
}

func revokePublicLink(c *cli.Context) error {
	id := c.Args().First()
	if id == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	ctx := util.GetContextWithAuth()
	_, err = client.RevokePublicLink(ctx, &api.ShareIDReq{Id: id})
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	return nil
}

func listPublicLinks(c *cli.Context) error {
	ctx := util.GetContextWithAuth()
	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	stream, err := client.ListPublicLinks(ctx, &api.EmptyReq{})
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	lines := []string{"#Token|Protected|Expires|ReadOnly|Modified|Path"}
	for {
		linkRes, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return cli.NewExitError(err, 1)
		}
		if linkRes.Status != api.StatusCode_OK {
			return cli.NewExitError(linkRes.Status, 1)
		}
		link := linkRes.PublicLink
		line := fmt.Sprintf("%s|%t|%d|%t|%d|%s", link.Token, link.Protected, link.Expires, link.ReadOnly, link.Mtime, link.Path)
		lines = append(lines, line)
	}
	fmt.Fprintln(c.App.Writer, columnize.SimpleFormat(lines))
	return nil
}

func updatePublicLink(c *cli.Context) error {
	id := c.Args().First()
	if id == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	req := &api.UpdateLinkReq{Id: id}

	if c.Bool("set-expiration") {
		req.UpdateExpiration = true
		if c.String("expiration") != "" {
			t, err := time.Parse("2006-01-02 03:04:05", c.String("expiration"))
			if err != nil {
				return cli.NewExitError(err, 1)
			}
			req.Expiration = uint64(t.Unix())
		}
	}

	if c.Bool("set-password") {
		req.Password = c.String("password")
		req.UpdatePassword = true

	}

	if c.Bool("set-read-only") {
		req.UpdateReadOnly = true
		req.ReadOnly = c.Bool("read-only")
	}

	ctx := util.GetContextWithAuth()
	linkRes, err := client.UpdatePublicLink(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if linkRes.Status != api.StatusCode_OK {
		return cli.NewExitError(linkRes.Status, 1)
	}
	link := linkRes.PublicLink

	modified := time.Unix(int64(link.Mtime), 0).Format(time.RFC3339)
	expires := time.Unix(int64(link.Expires), 0).Format(time.RFC3339)
	fmt.Fprintf(c.App.Writer, "Token: %s\nProtected: %t\nReadOnly: %t\nModify: %s Timestamp: %d\nExpires: %s Timestamp: %d\nPath: %s\n", link.Token, link.Protected, link.ReadOnly, modified, link.Mtime, expires, link.Expires, link.Path)
	return nil
}

func createFolderShare(c *cli.Context) {
	fmt.Println("not implemented")
}

func listFolderShares(c *cli.Context) {
	fmt.Println("not implemented")
}

func removeFolderShare(c *cli.Context) {
	fmt.Println("not implemented")
}
func updateFolderShare(c *cli.Context) {
	fmt.Println("not implemented")
}
func listReceivedShares(c *cli.Context) {
	fmt.Println("not implemented")
}
func mountReceivedShare(c *cli.Context) {
	fmt.Println("not implemented")
}
func unmountReceivedShare(c *cli.Context) {
	fmt.Println("not implemented")
}
