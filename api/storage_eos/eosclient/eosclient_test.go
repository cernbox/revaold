package eosclient

import (
	"context"
	"fmt"
	"testing"
)

var opt = &Options{
	URL:           "root://eosuat.cern.ch",
	EnableLogging: true,
}

var client, _ = New(opt)

var username = "gonzalhu"
var home = "/eos/scratch/user/g/gonzalhu"
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
