package sharesvc

import (
	"gitlab.com/labkode/reva/api"
	"golang.org/x/net/context"

	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
)

func New(lm api.PublicLinkManager) api.ShareServer {
	return &svc{linkManager: lm}
}

type svc struct {
	linkManager api.PublicLinkManager
}

func (s *svc) AddFolderShare(ctx context.Context, req *api.NewFolderShareReq) (*api.FolderShare, error) {
	return &api.FolderShare{}, nil
}

func (s *svc) UpdateFolderShare(ctx context.Context, req *api.UpdateFolderShareReq) (*api.Empty, error) {
	return &api.Empty{}, nil
}

func (s *svc) UnshareFolder(ctx context.Context, req *api.UnshareFolderReq) (*api.Empty, error) {
	return &api.Empty{}, nil
}

func (s *svc) ListPublicLinks(req *api.Empty, stream api.Share_ListPublicLinksServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	links, err := s.linkManager.ListPublicLinks(ctx)
	if err != nil {
		l.Error("error listing public links", zap.Error(err))
		return err
	}
	for _, link := range links {
		if err := stream.Send(link); err != nil {
			l.Error("error streaming link", zap.Error(err))
			return err
		}
	}
	return nil
}
func (s *svc) CreatePublicLink(ctx context.Context, req *api.NewLinkReq) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	opts := &api.PublicLinkOptions{
		Password:   req.Password,
		Expiration: req.Expires,
		ReadOnly:   req.ReadOnly,
	}

	publicLink, err := s.linkManager.CreatePublicLink(ctx, req.Path, opts)
	if err != nil {
		l.Error("error creating public link", zap.Error(err))
		return nil, err
	}
	return publicLink, nil
}

func (s *svc) InspectPublicLink(ctx context.Context, req *api.TokenReq) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	publicLink, err := s.linkManager.InspectPublicLink(ctx, req.Token)
	if err != nil {
		l.Error("error inspecting public link", zap.Error(err))
		return nil, err
	}
	return publicLink, nil
}

func (s *svc) RevokePublicLink(ctx context.Context, req *api.TokenReq) (*api.Empty, error) {
	l := ctx_zap.Extract(ctx)
	err := s.linkManager.RevokePublicLink(ctx, req.Token)
	if err != nil {
		l.Error("error revoking public link", zap.Error(err))
		return nil, err
	}
	return &api.Empty{}, nil
}

func (s *svc) UpdatePublicLink(ctx context.Context, req *api.UpdateLinkReq) (*api.PublicLink, error) {
	l := ctx_zap.Extract(ctx)
	opts := &api.PublicLinkOptions{
		Password:         req.Password,
		Expiration:       req.Expiration,
		ReadOnly:         req.ReadOnly,
		UpdatePassword:   req.UpdatePassword,
		UpdateExpiration: req.UpdateExpiration,
		UpdateReadOnly:   req.UpdateReadOnly,
	}

	publicLink, err := s.linkManager.UpdatePublicLink(ctx, req.Token, opts)
	if err != nil {
		l.Error("error updating public link", zap.Error(err))
		return nil, err
	}
	return publicLink, nil
}

func (s *svc) ListFolderShares(req *api.ListFolderSharesReq, stream api.Share_ListFolderSharesServer) error {
	return nil
}

func (s *svc) ListReceivedShares(req *api.Empty, stream api.Share_ListReceivedSharesServer) error {
	return nil
}

func (s *svc) MountReceivedShare(ctx context.Context, req *api.ReceivedShareReq) (*api.Empty, error) {
	return &api.Empty{}, nil
}

func (s *svc) UnmountReceivedShare(ctx context.Context, req *api.ReceivedShareReq) (*api.Empty, error) {
	return &api.Empty{}, nil
}
