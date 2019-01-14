package sharecmd

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cernbox/revaold/api"
	"github.com/cernbox/revaold/reva-cli/util"

	"github.com/codegangsta/cli"
	"github.com/ryanuber/columnize"
)

var CreateFolderShareCommand = cli.Command{
	Name:      "folder-share-create",
	Usage:     "Creates a folder share",
	ArgsUsage: "Usage: folder-share-create <path> <recipient-type> <recipient> <read-only>",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "read-write",
			Usage: "Sets the share to read-write so people can add/delete files",
		},
	},
	Action: createFolderShare,
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
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "read-write",
			Usage: "Sets the share to read-write so people can add/delete files",
		},
	},
	Action: updateFolderShare,
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
	fmt.Fprintf(c.App.Writer, "ID: %s\nToken: %s\nProtected: %t\nReadOnly: %t\nModify: %s Timestamp: %d\nExpires: %s Timestamp: %d\nPath: %s\n", link.Id, link.Token, link.Protected, link.ReadOnly, modified, link.Mtime, expires, link.Expires, link.Path)
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

	stream, err := client.ListPublicLinks(ctx, &api.ListPublicLinksReq{})
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	lines := []string{"#ID|Token|Protected|Expires|ReadOnly|Modified|Path"}
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
		line := fmt.Sprintf("%s|%s|%t|%d|%t|%d|%s", link.Id, link.Token, link.Protected, link.Expires, link.ReadOnly, link.Mtime, link.Path)
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

func getRecipientType(t string) (api.ShareRecipient_RecipientType, error) {
	switch t {
	case "user":
		return api.ShareRecipient_USER, nil
	case "group":
		return api.ShareRecipient_GROUP, nil
	case "unix-group":
		return api.ShareRecipient_UNIX, nil
	default:
		return 0, errors.New("unknow recipient type")
	}
}

func getRecipientTypeHuman(t api.ShareRecipient_RecipientType) string {
	switch t {
	case api.ShareRecipient_USER:
		return "user"
	case api.ShareRecipient_GROUP:
		return "group"
	case api.ShareRecipient_UNIX:
		return "unix-group"
	default:
		return "unknown"
	}

}

func createFolderShare(c *cli.Context) error {
	if len(c.Args()) < 3 {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	path := c.Args().First()
	recipientTypeString := c.Args().Get(1)
	recipient := c.Args().Get(2)
	readWrite := c.Bool("read-write")

	recipientType, err := getRecipientType(recipientTypeString)
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	if path == "" || recipientTypeString == "" || recipient == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	req := &api.NewFolderShareReq{Path: path, ReadOnly: !readWrite, Recipient: &api.ShareRecipient{Identity: recipient, Type: recipientType}}

	ctx := util.GetContextWithAuth()
	res, err := client.AddFolderShare(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if res.Status != api.StatusCode_OK {
		return cli.NewExitError(res.Status, 1)
	}
	share := res.FolderShare

	modified := time.Unix(int64(share.Mtime), 0).Format(time.RFC3339)

	fmt.Fprintf(c.App.Writer, "ID: %s\nReadOnly: %t\nType: %s Recipient: %s\nModify: %s Timestamp: %d\nPath: %s\n", share.Id, share.ReadOnly, recipientTypeString, share.Recipient.Identity, modified, share.Mtime, share.Path)
	return nil
}

func listFolderShares(c *cli.Context) error {
	ctx := util.GetContextWithAuth()
	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	stream, err := client.ListFolderShares(ctx, &api.ListFolderSharesReq{})
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	lines := []string{"#ID|ReadOnly|Type|Recipient|Modified|Path"}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return cli.NewExitError(err, 1)
		}
		if res.Status != api.StatusCode_OK {
			return cli.NewExitError(res.Status, 1)
		}
		share := res.FolderShare
		recipientType := getRecipientTypeHuman(share.Recipient.Type)
		line := fmt.Sprintf("%s|%t|%s|%s|%d|%s", share.Id, share.ReadOnly, recipientType, share.Recipient.Identity, share.Mtime, share.Path)
		lines = append(lines, line)
	}
	fmt.Fprintln(c.App.Writer, columnize.SimpleFormat(lines))
	return nil
}

func removeFolderShare(c *cli.Context) error {
	id := c.Args().First()
	if id == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	ctx := util.GetContextWithAuth()
	req := &api.UnshareFolderReq{Id: id}
	res, err := client.UnshareFolder(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if res.Status != api.StatusCode_OK {
		return cli.NewExitError(res.Status, 1)
	}
	return nil
}

func updateFolderShare(c *cli.Context) error {
	id := c.Args().First()
	if id == "" {
		return cli.NewExitError(c.Command.ArgsUsage, 1)
	}

	readWrite := c.Bool("read-write")

	req := &api.UpdateFolderShareReq{Id: id, ReadOnly: !readWrite, UpdateReadOnly: true}
	ctx := util.GetContextWithAuth()
	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	res, err := client.UpdateFolderShare(ctx, req)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if res.Status != api.StatusCode_OK {
		return cli.NewExitError(res.Status, 1)
	}

	share := res.FolderShare
	modified := time.Unix(int64(share.Mtime), 0).Format(time.RFC3339)

	recipientTypeString := getRecipientTypeHuman(share.Recipient.Type)
	fmt.Fprintf(c.App.Writer, "ID: %s\nReadOnly: %t\nType: %s Recipient: %s\nModify: %s Timestamp: %d\nPath: %s\n", share.Id, share.ReadOnly, recipientTypeString, share.Recipient.Identity, modified, share.Mtime, share.Path)
	return nil

}
func listReceivedShares(c *cli.Context) error {
	ctx := util.GetContextWithAuth()
	client, err := util.GetSharingClient()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	stream, err := client.ListReceivedShares(ctx, &api.EmptyReq{})
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	lines := []string{"#ID|ReadOnly|Type|From|To|Modified|Path"}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return cli.NewExitError(err, 1)
		}
		if res.Status != api.StatusCode_OK {
			return cli.NewExitError(res.Status, 1)
		}
		share := res.Share
		recipientType := getRecipientTypeHuman(share.Recipient.Type)
		line := fmt.Sprintf("%s|%t|%s|%s|%s|%d|%s", share.Id, share.ReadOnly, recipientType, share.OwnerId, share.Recipient.Identity, share.Mtime, share.Path)
		lines = append(lines, line)
	}
	fmt.Fprintln(c.App.Writer, columnize.SimpleFormat(lines))
	return nil
}

func mountReceivedShare(c *cli.Context) {
	fmt.Println("not implemented")
}
func unmountReceivedShare(c *cli.Context) {
	fmt.Println("not implemented")
}
