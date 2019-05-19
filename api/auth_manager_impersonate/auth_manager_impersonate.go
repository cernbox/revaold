package auth_manager_impersonate

import (
	"context"
	"errors"

	"github.com/cernbox/revaold/api"
)

type authManager struct{}

func New() api.AuthManager {
	return &authManager{}
}

func (am *authManager) Authenticate(ctx context.Context, clientID, clientSecret string) (*api.User, error) {
	return &api.User{AccountId: clientID, Groups: []string{}}, nil
}

func (am *authManager) AuthenticateToken(ctx context.Context, token string) (*api.User, error) {
	return nil, errors.New("Tokens not supported")
}
