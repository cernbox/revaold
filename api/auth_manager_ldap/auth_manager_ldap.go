package auth_manager_ldap

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/cernbox/revaold/api"
	"gopkg.in/ldap.v2"
)

type authManager struct {
	hostname     string
	port         int
	baseDN       string
	filter       string
	bindUsername string
	bindPassword string
}

func New(hostname string, port int, basedn, filter, bindclientID, bindpassword string) api.AuthManager {
	return &authManager{
		hostname:     hostname,
		port:         port,
		baseDN:       basedn,
		filter:       filter,
		bindUsername: bindclientID,
		bindPassword: bindpassword,
	}
}

func (am *authManager) Authenticate(ctx context.Context, clientID, clientSecret string) (*api.User, error) {
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", am.hostname, am.port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer l.Close()

	// First bind with a read only user
	err = l.Bind(am.bindUsername, am.bindPassword)
	if err != nil {
		return nil, err
	}

	// Search for the given clientID
	searchRequest := ldap.NewSearchRequest(
		am.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(am.filter, clientID),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) != 1 {
		return nil, api.NewError(api.UserNotFoundErrorCode)
	}

	for _, e := range sr.Entries {
		e.Print()
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, clientSecret)
	if err != nil {
		return nil, err
	}
	//TODO(labkode): add groups support

	return &api.User{AccountId: clientID, Groups: []string{}}, nil
}
