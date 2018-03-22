package linkmanager

import (
	"context"
	"time"

	"github.com/cernbox/reva/api"

	"github.com/satori/go.uuid"
)

func NewPublicLinkManager() api.PublicLinkManager {
	return &linkManager{links: []*api.PublicLink{}}
}

type linkManager struct {
	links []*api.PublicLink
}

// TODO(labkode): handle nil opt
func (lm *linkManager) CreatePublicLink(ctx context.Context, path string, opt *api.PublicLinkOptions) (*api.PublicLink, error) {
	uuid, _ := uuid.NewV4()
	token := uuid.String()
	link := &api.PublicLink{
		Path:      path,
		Token:     token,
		Protected: opt.Password != "",
		ReadOnly:  opt.ReadOnly,
		Expires:   opt.Expiration,
		Mtime:     uint64(time.Now().Local().Unix()),
	}

	now := uint64(time.Now().Local().Unix())
	if link.Expires == 0 {
		link.Expires = now
	} else {
		// TOOD(labkode): validate the expire date is not in the past
		if link.Expires <= now {
			return nil, api.NewError(api.PublicLinkInvalidExpireDateErrorCode)
		}
	}

	lm.links = append(lm.links, link)
	return link, nil
}

// TODO(labkode): handle nil opt
func (lm *linkManager) UpdatePublicLink(ctx context.Context, token string, opt *api.PublicLinkOptions) (*api.PublicLink, error) {
	for i, l := range lm.links {
		if l.Token == token {
			l.Protected = opt.Password != ""
			if opt.Expiration > 0 {
				now := uint64(time.Now().Local().Unix())
				// TOOD(labkode): validate the expire date is not in the past
				if opt.Expiration <= now {
					return nil, api.NewError(api.PublicLinkInvalidExpireDateErrorCode)
				}
				l.Expires = opt.Expiration
			}
			l.ReadOnly = opt.ReadOnly
			l.Mtime = uint64(time.Now().Local().Unix())
			lm.links[i] = l
			return l, nil
		}
	}
	return nil, api.NewError(api.PublicLinkNotFoundErrorCode).WithMessage(token)
}

func (lm *linkManager) InspectPublicLink(ctx context.Context, token string) (*api.PublicLink, error) {
	for _, l := range lm.links {
		if l.Token == token {
			return l, nil
		}
	}
	return nil, api.NewError(api.PublicLinkNotFoundErrorCode).WithMessage(token)
}

func (lm *linkManager) ListPublicLinks(ctx context.Context) ([]*api.PublicLink, error) {
	return lm.links, nil
}

func (lm *linkManager) RevokePublicLink(ctx context.Context, token string) error {
	for i, l := range lm.links {
		if l.Token == token {
			lm.links[len(lm.links)-1], lm.links[i] = lm.links[i], lm.links[len(lm.links)-1]
			lm.links = lm.links[:len(lm.links)-1]
			return nil
		}
	}
	return api.NewError(api.PublicLinkNotFoundErrorCode).WithMessage(token)
}
