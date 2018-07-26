package taggersvc

import (
	"github.com/cernbox/reva/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
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
