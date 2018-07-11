package user_manager_cboxgroupd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cernbox/reva/api"
	"io/ioutil"
	"net/http"

	"go.uber.org/zap"
)

type Options struct {
	Logger *zap.Logger

	CBOXGroupDaemonURI    string
	CBOXGroupDaemonSecret string
}

func (opt *Options) init() {
	if opt.CBOXGroupDaemonURI == "" {
		opt.CBOXGroupDaemonURI = "http://localhost:2002"
	}
}

func New(opt *Options) api.UserManager {
	if opt == nil {
		opt = &Options{}
	}

	opt.init()
	return &userManager{cboxGroupDaemonSecret: opt.CBOXGroupDaemonSecret, cboxGroupDaemonURI: opt.CBOXGroupDaemonURI}
}

type userManager struct {
	cboxGroupDaemonURI    string
	cboxGroupDaemonSecret string
	logger                *zap.Logger
}

func (um *userManager) GetUserGroups(ctx context.Context, username string) ([]string, error) {
	groups := []string{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/api/v1/membership/usergroups/%s", um.cboxGroupDaemonURI, username)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		um.logger.Error("", zap.Error(err))
		return groups, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", um.cboxGroupDaemonSecret))
	res, err := client.Do(req)
	if err != nil {
		um.logger.Error("", zap.Error(err))
		return groups, err
	}

	if res.StatusCode != http.StatusOK {
		err := errors.New("error calling cboxgroupd membership")
		um.logger.Error("", zap.Int("http_code", res.StatusCode), zap.Error(err))
		return groups, err
	}

	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		um.logger.Error("", zap.Error(err))
		return groups, err
	}

	err = json.Unmarshal(body, &groups)
	if err != nil {
		um.logger.Error("", zap.Error(err))
		return groups, err
	}
	return groups, nil
}

type groupResponse []string

/*
// search calls the cboxgroupd daemon for finding entries.
func (p *proxy) search(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")

	//itemType := r.URL.Query().Get("itemType")
	//perPage := r.URL.Query().Get("perPage")

	if search == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	searchTarget := p.getSearchTarget(search)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/api/v1/search/%s", p.cboxGroupDaemonURI, search)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.cboxGroupDaemonSecret))
	res, err := client.Do(req)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.StatusCode != http.StatusOK {
		p.logger.Error("error calling cboxgroupd search", zap.Int("status", res.StatusCode))
		w.WriteHeader(res.StatusCode)
		return

	}

	searchEntries := []*searchEntry{}
	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		p.logger.Error("", zap.Error(err))
		w.WriteHeader(res.StatusCode)
		return
	}

}
*/
