package authsvc

import (
	"github.com/cernbox/reva/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

func New(am api.AuthManager, tm api.TokenManager) api.AuthServer {
	return &svc{am: am, tm: tm}
}

type svc struct {
	am api.AuthManager
	tm api.TokenManager
}

func (s *svc) CreateToken(ctx context.Context, req *api.CreateTokenReq) (*api.TokenResponse, error) {
	l := ctx_zap.Extract(ctx)
	user, err := s.am.Authenticate(ctx, req.ClientId, req.ClientSecret)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	token, err := s.tm.ForgeToken(ctx, user)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	t := &api.Token{Token: token}
	tokenResponse := &api.TokenResponse{Token: t}
	return tokenResponse, nil
}

func (s *svc) VerifyToken(ctx context.Context, req *api.VerifyTokenReq) (*api.UserResponse, error) {
	l := ctx_zap.Extract(ctx)
	token := req.Token
	u, err := s.tm.VerifyToken(ctx, token)
	if err != nil {
		l.Error("token invalid", zap.Error(err))
		return nil, api.NewError(api.TokenInvalidErrorCode).WithMessage(err.Error())
	}
	userRes := &api.UserResponse{User: u}
	return userRes, nil
}

// Override the Auth function to avoid checking the bearer token for this service
// https://github.com/grpc-ecosystem/go-grpc-middleware/tree/master/auth#type-serviceauthfuncoverride
func (s *svc) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, nil
}
