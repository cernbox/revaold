package auth_manager_oauth_ldap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/cernbox/revaold/api"
	"github.com/cernbox/revaold/api/auth_manager_ldap"
	"go.uber.org/zap"
)

type authManager struct {
	ldapManager api.AuthManager
	dbUser      string
	dbPass      string
	dbHost      string
	dbPort      int
	dbName      string
	logger      *zap.Logger
}

func New(hostname string, port int, basedn, filter, bindclientID, bindpassword, dbUser, dbPass, dbHost, dbName string, dbPort int, logger *zap.Logger) api.AuthManager {
	return &authManager{
		ldapManager: auth_manager_ldap.New(hostname, port, basedn, filter, bindclientID, bindpassword),
		dbUser:      dbUser,
		dbPass:      dbPass,
		dbHost:      dbHost,
		dbPort:      dbPort,
		dbName:      dbName,
		logger:      logger,
	}
}

func (am *authManager) Authenticate(ctx context.Context, clientID, clientSecret string) (*api.User, error) {
	return am.ldapManager.Authenticate(ctx, clientID, clientSecret)
}

func (am *authManager) AuthenticateToken(ctx context.Context, token string) (*api.User, error) {

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", am.dbUser, am.dbPass, am.dbHost, am.dbPort, am.dbName))
	defer db.Close()
	if err != nil {
		am.logger.Error("CANNOT CONNECT TO MYSQL SERVER", zap.String("HOSTNAME", am.dbHost), zap.Int("PORT", am.dbPort), zap.String("DB", am.dbName))
		return nil, err
	}

	var user string
	var expires int64

	query := "SELECT user_id, expires FROM oc_oauth2_access_tokens WHERE token=?"
	err = db.QueryRow(query, token).Scan(&user, &expires)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("oAuth token not found")
		}
		am.logger.Error("CANNOT QUERY STATEMENT")
		return nil, err
	}
	now := time.Now().Unix()

	if expires < now {
		return nil, errors.New("oAuth token expired")
	}
	return &api.User{AccountId: user, Groups: []string{}}, nil
}
