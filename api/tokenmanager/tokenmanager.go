package tokenmanager

import (
	"context"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"gitlab.com/labkode/reva/api"
	"go.uber.org/zap"
)

func New(signSecret string) api.TokenManager {
	return &tokenManager{signSecret: signSecret}
}

type tokenManager struct {
	signSecret string
}

func (tm *tokenManager) ForgeToken(ctx context.Context, user *api.User) (string, error) {
	l := ctx_zap.Extract(ctx)
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["account_id"] = user.AccountID
	claims["groups"] = user.Groups
	claims["exp"] = time.Now().Add(time.Second * time.Duration(3600))
	tokenString, err := token.SignedString([]byte(tm.signSecret))
	if err != nil {
		l.Error("", zap.Error(err))
		return "", err
	}
	return tokenString, nil
}
