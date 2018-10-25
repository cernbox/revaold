package sharesvc

import (
	"github.com/cernbox/reva/api"
	"golang.org/x/net/context"

	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func New(lm api.PublicLinkManager, sm api.ShareManager) api.ShareServer {
	return &svc{linkManager: lm, shareManager: sm}
}

type svc struct {
	linkManager  api.PublicLinkManager
	shareManager api.ShareManager
}

func (s *svc) ListReceivedShares(req *api.EmptyReq, stream api.Share_ListReceivedSharesServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	shares, err := s.shareManager.ListReceivedShares(ctx)
	if err != nil {
		l.Error("error listing received folder shares", zap.Error(err))
		return err
	}
	for _, share := range shares {
		folderShareRes := &api.ReceivedShareResponse{Share: share}
		if err := stream.Send(folderShareRes); err != nil {
			l.Error("error streaming received folder share", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) IsPublicLinkProtected(ctx context.Context, req *api.PublicLinkTokenReq) (*api.IsPublicLinkProtectedResponse, error) {
	l := ctx_zap.Extract(ctx)
	ok, err := s.linkManager.IsPublicLinkProtected(ctx, req.Token)
	if err != nil {
		l.Error("error checking if public link is protected", zap.Error(err))
		return nil, err
	}
	res := &api.IsPublicLinkProtectedResponse{Protected: ok}
	return res, nil
}

func (s *svc) MountReceivedShare(ctx context.Context, req *api.ReceivedShareReq) (*api.EmptyResponse, error) {
	return &api.EmptyResponse{}, nil
}

func (s *svc) UnmountReceivedShare(ctx context.Context, req *api.ReceivedShareReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	err := s.shareManager.UnmountReceivedShare(ctx, req.ShareId)
	if err != nil {
		err = errors.Wrapf(err, "error unmounting received share: id=%s", req.ShareId)
		l.Error("", zap.Error(err))
		return nil, err
	}

	return &api.EmptyResponse{}, nil
}

func (s *svc) ListFolderShares(req *api.ListFolderSharesReq, stream api.Share_ListFolderSharesServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	shares, err := s.shareManager.ListFolderShares(ctx, req.Path)
	if err != nil {
		l.Error("error listing folder shares", zap.Error(err))
		return err
	}
	for _, share := range shares {
		folderShareRes := &api.FolderShareResponse{FolderShare: share}
		if err := stream.Send(folderShareRes); err != nil {
			l.Error("error streaming folder share", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) GetFolderShare(ctx context.Context, req *api.ShareIDReq) (*api.FolderShareResponse, error) {
	l := ctx_zap.Extract(ctx)
	share, err := s.shareManager.GetFolderShare(ctx, req.Id)
	if err != nil {
		if api.IsErrorCode(err, api.FolderShareNotFoundErrorCode) {
			return &api.FolderShareResponse{Status: api.StatusCode_FOLDER_SHARE_NOT_FOUND}, nil
		}
		l.Error("error gettting folder share", zap.Error(err))
		return nil, err
	}
	res := &api.FolderShareResponse{FolderShare: share}
	return res, nil

}

func (s *svc) AddFolderShare(ctx context.Context, req *api.NewFolderShareReq) (*api.FolderShareResponse, error) {
	l := ctx_zap.Extract(ctx)
	share, err := s.shareManager.AddFolderShare(ctx, req.Path, req.Recipient, req.ReadOnly)
	if err != nil {
		l.Error("error creating folder share", zap.Error(err))
		return nil, err
	}
	folderShareRes := &api.FolderShareResponse{FolderShare: share}
	return folderShareRes, nil
}

func (s *svc) UpdateFolderShare(ctx context.Context, req *api.UpdateFolderShareReq) (*api.FolderShareResponse, error) {
	l := ctx_zap.Extract(ctx)
	share, err := s.shareManager.UpdateFolderShare(ctx, req.Id, req.UpdateReadOnly, req.ReadOnly)
	if err != nil {
		l.Error("error updating folder share", zap.Error(err))
		return nil, err
	}
	folderShareRes := &api.FolderShareResponse{FolderShare: share}
	return folderShareRes, nil
}

func (s *svc) UnshareFolder(ctx context.Context, req *api.UnshareFolderReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	err := s.shareManager.Unshare(ctx, req.Id)
	if err != nil {
		l.Error("error deleting folder share", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) ListPublicLinks(req *api.ListPublicLinksReq, stream api.Share_ListPublicLinksServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	links, err := s.linkManager.ListPublicLinks(ctx, req.Path)
	if err != nil {
		l.Error("error listing public links", zap.Error(err))
		return err
	}
	for _, link := range links {
		publicLinkRes := &api.PublicLinkResponse{PublicLink: link}
		if err := stream.Send(publicLinkRes); err != nil {
			l.Error("error streaming link", zap.Error(err))
			return err
		}
	}
	return nil
}
func (s *svc) CreatePublicLink(ctx context.Context, req *api.NewLinkReq) (*api.PublicLinkResponse, error) {
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
	publicLinkRes := &api.PublicLinkResponse{PublicLink: publicLink}
	return publicLinkRes, nil
}

func (s *svc) InspectPublicLink(ctx context.Context, req *api.ShareIDReq) (*api.PublicLinkResponse, error) {
	l := ctx_zap.Extract(ctx)
	publicLink, err := s.linkManager.InspectPublicLink(ctx, req.Id)
	if err != nil {
		if api.IsErrorCode(err, api.PublicLinkNotFoundErrorCode) {
			return &api.PublicLinkResponse{Status: api.StatusCode_PUBLIC_LINK_NOT_FOUND}, nil
		}
		l.Error("error inspecting public link", zap.Error(err))
		return nil, err
	}
	publicLinkRes := &api.PublicLinkResponse{PublicLink: publicLink}
	return publicLinkRes, nil
}

func (s *svc) RevokePublicLink(ctx context.Context, req *api.ShareIDReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	err := s.linkManager.RevokePublicLink(ctx, req.Id)
	if err != nil {
		l.Error("error revoking public link", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) UpdatePublicLink(ctx context.Context, req *api.UpdateLinkReq) (*api.PublicLinkResponse, error) {
	l := ctx_zap.Extract(ctx)
	opts := &api.PublicLinkOptions{
		Password:         req.Password,
		Expiration:       req.Expiration,
		ReadOnly:         req.ReadOnly,
		UpdatePassword:   req.UpdatePassword,
		UpdateExpiration: req.UpdateExpiration,
		UpdateReadOnly:   req.UpdateReadOnly,
	}

	publicLink, err := s.linkManager.UpdatePublicLink(ctx, req.Id, opts)
	if err != nil {
		l.Error("error updating public link", zap.Error(err))
		return nil, err
	}
	publicLinkRes := &api.PublicLinkResponse{PublicLink: publicLink}
	return publicLinkRes, nil
}
