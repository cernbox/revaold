package token_manager_jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cernbox/reva/api"
	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

func New(signSecret string) api.TokenManager {
	return &tokenManager{signSecret: signSecret}
}

type tokenManager struct {
	signSecret string
}

func (tm *tokenManager) ForgeUserToken(ctx context.Context, user *api.User) (string, error) {
	l := ctx_zap.Extract(ctx)
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["account_id"] = user.AccountId
	claims["groups"] = user.Groups
	claims["exp"] = time.Now().Add(time.Second * time.Duration(3600))
	tokenString, err := token.SignedString([]byte(tm.signSecret))
	if err != nil {
		l.Error("", zap.Error(err))
		return "", err
	}
	return tokenString, nil
}

func (tm *tokenManager) DismantleUserToken(ctx context.Context, token string) (*api.User, error) {
	l := ctx_zap.Extract(ctx)
	rawToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(tm.signSecret), nil
	})
	if err != nil {
		l.Error("invalid token", zap.Error(err), zap.String("token", token))
		return nil, err
	}
	if !rawToken.Valid {
		l.Error("invalid token", zap.Error(err), zap.String("token", token))
		return nil, err

	}

	claims := rawToken.Claims.(jwt.MapClaims)
	accountID, ok := claims["account_id"].(string)
	if !ok {
		return nil, errors.New("account_id claim is not a string")
	}

	rawGroups, ok := claims["groups"].([]interface{})
	if !ok {
		return nil, errors.New("groups claim is not a []interface{}")
	}
	groups := []string{}
	for _, g := range rawGroups {
		group, ok := g.(string)
		if !ok {
			err := errors.New(fmt.Sprintf("group %+v can not be casted to string", g))
			l.Error("", zap.Error(err))
			return nil, err
		}
		groups = append(groups, group)
	}

	user := &api.User{
		AccountId: accountID,
		Groups:    groups,
	}
	return user, nil
}

func (tm *tokenManager) ForgePublicLinkToken(ctx context.Context, pl *api.PublicLink) (string, error) {
	l := ctx_zap.Extract(ctx)
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["token"] = pl.Token
	claims["owner"] = pl.OwnerId
	claims["exp"] = time.Now().Add(time.Second * time.Duration(3600))
	tokenString, err := token.SignedString([]byte(tm.signSecret))
	if err != nil {
		l.Error("", zap.Error(err))
		return "", err
	}
	return tokenString, nil
}

func (tm *tokenManager) DismantlePublicLinkToken(ctx context.Context, token string) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	rawToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(tm.signSecret), nil
	})
	if err != nil {
		l.Error("invalid token", zap.Error(err), zap.String("token", token))
		return nil, err
	}
	if !rawToken.Valid {
		l.Error("invalid token", zap.Error(err), zap.String("token", token))
		return nil, err

	}

	claims := rawToken.Claims.(jwt.MapClaims)
	token, ok := claims["token"].(string)
	if !ok {
		return nil, errors.New("token claim is not a string")
	}
	owner, ok := claims["owner"].(string)
	if !ok {
		return nil, errors.New("owner claim is not a string")
	}

	pl := &api.PublicLink{
		Token:   token,
		OwnerId: owner,
	}
	return pl, nil
}
