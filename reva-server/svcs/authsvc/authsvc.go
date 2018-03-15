package authsvc

import (
	"gitlab.com/labkode/reva/api"
	"golang.org/x/net/context"
)

func New(am api.AuthManager, tm api.TokenManager) api.AuthServer {
	return &svc{am: am, tm: tm}
}

type svc struct {
	am api.AuthManager
	tm api.TokenManager
}

func (s *svc) CreateToken(ctx context.Context, req *api.CreateTokenReq) (*api.Token, error) {
	user, err := s.am.Authenticate(ctx, req.ClientId, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	token, err := s.tm.ForgeToken(ctx, user)
	if err != nil {
		return nil, err
	}
	t := &api.Token{Token: token}
	return t, nil
}

func (s *svc) VerifyToken(ctx context.Context, req *api.VerifyTokenReq) (*api.Empty, error) {
	return &api.Empty{}, nil
}

// Override the Auth function to avoid checking the bearer token for this service
// https://github.com/grpc-ecosystem/go-grpc-middleware/tree/master/auth#type-serviceauthfuncoverride
func (s *svc) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, nil
}
