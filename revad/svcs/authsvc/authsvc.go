package authsvc

import (
	"github.com/cernbox/revaold/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

func New(am api.AuthManager, tm api.TokenManager, lm api.PublicLinkManager) api.AuthServer {
	return &svc{am: am, tm: tm, lm: lm}
}

type svc struct {
	am api.AuthManager
	tm api.TokenManager
	lm api.PublicLinkManager
}

func (s *svc) ForgeUserToken(ctx context.Context, req *api.ForgeUserTokenReq) (*api.TokenResponse, error) {
	l := ctx_zap.Extract(ctx)
	user, err := s.am.Authenticate(ctx, req.ClientId, req.ClientSecret)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}

	token, err := s.tm.ForgeUserToken(ctx, user)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	tokenResponse := &api.TokenResponse{Token: token}
	return tokenResponse, nil
}

func (s *svc) DismantleUserToken(ctx context.Context, req *api.TokenReq) (*api.UserResponse, error) {
	l := ctx_zap.Extract(ctx)
	token := req.Token
	u, err := s.tm.DismantleUserToken(ctx, token)
	if err != nil {
		l.Warn("token invalid", zap.Error(err))
		res := &api.UserResponse{Status: api.StatusCode_TOKEN_INVALID}
		return res, nil
		//return nil, api.NewError(api.TokenInvalidErrorCode).WithMessage(err.Error())
	}
	userRes := &api.UserResponse{User: u}
	return userRes, nil
}

func (s *svc) ForgePublicLinkToken(ctx context.Context, req *api.ForgePublicLinkTokenReq) (*api.TokenResponse, error) {
	l := ctx_zap.Extract(ctx)
	pl, err := s.lm.AuthenticatePublicLink(ctx, req.Token, req.Password)
	if err != nil {
		if api.IsErrorCode(err, api.PublicLinkInvalidPasswordErrorCode) {
			return &api.TokenResponse{Status: api.StatusCode_PUBLIC_LINK_INVALID_PASSWORD}, nil
		}
		l.Error("", zap.Error(err))
		return nil, err
	}

	token, err := s.tm.ForgePublicLinkToken(ctx, pl)
	if err != nil {
		l.Warn("", zap.Error(err))
		return nil, err
	}
	tokenResponse := &api.TokenResponse{Token: token}
	return tokenResponse, nil
}

func (s *svc) DismantlePublicLinkToken(ctx context.Context, req *api.TokenReq) (*api.PublicLinkResponse, error) {
	l := ctx_zap.Extract(ctx)
	token := req.Token
	u, err := s.tm.DismantlePublicLinkToken(ctx, token)
	if err != nil {
		l.Error("token invalid", zap.Error(err))
		return nil, api.NewError(api.TokenInvalidErrorCode).WithMessage(err.Error())
	}
	userRes := &api.PublicLinkResponse{PublicLink: u}
	return userRes, nil
}

// Override the Auth function to avoid checking the bearer token for this service
// https://github.com/grpc-ecosystem/go-grpc-middleware/tree/master/auth#type-serviceauthfuncoverride
func (s *svc) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, nil
}
