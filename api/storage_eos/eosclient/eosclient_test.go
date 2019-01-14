package eosclient

import (
	"context"
	"fmt"
	"github.com/cernbox/revaold/api"
	"testing"
)

var opt = &Options{
	URL: "root://eoshome-g.cern.ch",
	//URL:           "root://eosuser-internal.cern.ch",
	EnableLogging: true,
}

var client, _ = New(opt)

var username = "gonzalhu"

var home = "/eos/user/g/gonzalhu/IVEN"

//var home = "/eos/user/opstest/"
var ctx = context.Background()

func TestList(t *testing.T) {
	entries, err := client.List(ctx, username, home)
	if err != nil {
		t.Fatal()
		return
	}
	for _, e := range entries {
		fmt.Println(e)
	}
}

func TestCreateDir(t *testing.T) {
	for i := 0; i < 10; i++ {
		err := client.CreateDir(ctx, username, fmt.Sprintf("%s/test-create-dir/test-%d", home, i))
		if err != nil {
			t.Fatal(err)
			return
		}
	}
}

func TestListRecycle(t *testing.T) {
	_, err := client.ListDeletedEntries(ctx, username)
	if err != nil {
		t.Fatal(err)
		return
	}
}
func TestQuota(t *testing.T) {
	max, used, err := client.GetQuota(ctx, username, "/eos/scratch/user/l/labradorsvc/Photos")
	if err != nil {
		t.Fatal(err)
		return
	}
	fmt.Println(max, used)

}

func TestVersion(t *testing.T) {
	version, err := client.getVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(version)
}

func TestAddACL(t *testing.T) {
	recipient := &api.ShareRecipient{
		Identity: "labradorsvc",
		Type:     api.ShareRecipient_USER,
	}
	err := client.AddACL(ctx, username, home, true, recipient, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRemoveACL(t *testing.T) {
	recipient := &api.ShareRecipient{
		Identity: "labradorsvc",
		Type:     api.ShareRecipient_USER,
	}
	err := client.RemoveACL(ctx, username, home, recipient, nil)
	if err != nil {
		t.Fatal(err)
	}
}
