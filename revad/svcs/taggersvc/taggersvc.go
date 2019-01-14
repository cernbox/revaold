package taggersvc

import (
	"github.com/cernbox/revaold/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

func New(tm api.TagManager) api.TaggerServer {
	return &svc{tm: tm}
}

type svc struct {
	tm api.TagManager
}

func (s *svc) GetTags(req *api.TagReq, stream api.Tagger_GetTagsServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	tags, err := s.tm.GetTagsForKey(ctx, req.TagKey)
	if err != nil {
		l.Error("error getting tags for key", zap.String("key", req.TagKey), zap.Error(err))
		return err
	}
	for _, tag := range tags {
		res := &api.TagResponse{Tag: tag}
		if err := stream.Send(res); err != nil {
			l.Error("error sending tag response", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) SetTag(ctx context.Context, req *api.TagReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.tm.SetTag(ctx, req.TagKey, req.TagVal, req.Path); err != nil {
		l.Error("error setting tag", zap.String("key", req.TagKey), zap.String("val", req.TagVal), zap.String("path", req.Path), zap.Error(err))
		return &api.EmptyResponse{Status: api.StatusCode_UNKNOWN}, nil
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) UnSetTag(ctx context.Context, req *api.TagReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.tm.UnSetTag(ctx, req.TagKey, req.TagVal, req.Path); err != nil {
		l.Error("error unsetting tag", zap.String("key", req.TagKey), zap.String("val", req.TagVal), zap.String("path", req.Path), zap.Error(err))
		return &api.EmptyResponse{Status: api.StatusCode_UNKNOWN}, nil
	}
	return &api.EmptyResponse{}, nil
}
