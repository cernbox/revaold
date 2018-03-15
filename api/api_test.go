package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOne(t *testing.T) {
	localFS := NewLocalFS("/tmp")
	mountOne := NewMount(localFS, "/one")
	mountTwo := NewMount(localFS, "/two")
	vfs := NewVFS()
	vfs.AddMount(context.Background(), mountOne)
	vfs.AddMount(context.Background(), mountTwo)

	finfos, err := vfs.ReadDir(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	for _, finfo := range finfos {
		t.Log(finfo)
	}

	finfos, err = vfs.ReadDir(context.Background(), "two")
	if err != nil {
		t.Fatal(err)
	}
	for _, finfo := range finfos {
		t.Log(finfo)
	}
}

func TestNotFound(t *testing.T) {
	localFS := NewLocalFS("/tmp")
	mountOne := NewMount(localFS, "/one")
	vfs := NewVFS()
	vfs.AddMount(context.Background(), mountOne)

	_, err := vfs.Stat(context.Background(), "/one/doesnotexists")
	if _, ok := err.(Error); !ok {
		t.Fatal("error is not correct type")
	}
}

func TestHandler(t *testing.T) {
	localFS := NewLocalFS("/tmp")
	mountOne := NewMount(localFS, "/one")
	vfs := NewVFS()
	vfs.AddMount(context.Background(), mountOne)
	handler := Stat(vfs)
	data := bytes.NewBufferString("{\"path\": \"one\"}")
	r, _ := http.NewRequest("POST", "/stat", data)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatal("fallou")
	}
}
