package storage_usermigration

import (
	"context"
	"testing"

	"github.com/cernbox/revaold/api"
)

func TestUnknownLetterReturnsNotFound(t *testing.T) {
	s, err := New(&Options{NewUserMap: map[string]api.Storage{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := api.ContextSetUser(context.Background(), &api.User{AccountId: "demo"})

	_, err = s.ListFolder(ctx, "/zzz/file")
	if !api.IsErrorCode(err, api.StorageNotFoundErrorCode) {
		t.Fatalf("expected StorageNotFound, got %v", err)
	}
	if err := s.RestoreRecycleEntry(ctx, "key"); err == nil {
		t.Fatal("expected error from RestoreRecycleEntry")
	}
}
