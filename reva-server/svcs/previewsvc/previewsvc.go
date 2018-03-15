package previewsvc

import (
	"gitlab.com/labkode/reva/api"
)

func New() api.PreviewServer {
	return new(svc)
}

type svc struct{}

func (s *svc) ReadPreview(req *api.PathReq, stream api.Preview_ReadPreviewServer) error {
	return nil
}
