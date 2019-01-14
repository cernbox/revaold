package auth_manager_impersonate

import (
	"context"
	"github.com/cernbox/revaold/api"
)

type authManager struct{}

func New() api.AuthManager {
	return &authManager{}
}

func (am *authManager) Authenticate(ctx context.Context, clientID, clientSecret string) (*api.User, error) {
	return &api.User{AccountId: clientID, Groups: []string{}}, nil
}
