package nopstorage

import (
	"context"
	"fmt"
	"testing"

	"gitlab.com/labkode/alustro/pkg"
)

var finfos = []*pkg.FileInfo{
	&pkg.FileInfo{
		Path:  "/test",
		Size:  120,
		IsDir: false,
	},
	&pkg.FileInfo{
		Path:  "/dir_1",
		Size:  0,
		IsDir: true,
	},
	&pkg.FileInfo{
		Path:  "/dir_1/file_1",
		Size:  100,
		IsDir: false,
	},
}
var opt = &Options{
	FileInfos: finfos,
}
var storage = New(opt)
var ctx = context.Background()

func TestList(t *testing.T) {
	finfos, err := storage.List(ctx, "/dir_1")
	if err != nil {
		t.Fatal(err)
		return
	}
	for _, fi := range finfos {
		fmt.Printf("%+v\n", fi)
	}
}
