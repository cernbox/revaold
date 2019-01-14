package storagesvc

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cernbox/revaold/api"

	"github.com/gofrs/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags/zap"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

func New(vs api.VirtualStorage, temporaryFolder string) api.StorageServer {
	s := new(svc)
	if temporaryFolder == "" {
		temporaryFolder = os.TempDir()
	}
	s.vs = vs
	s.temporaryFolder = temporaryFolder
	return s
}

type svc struct {
	vs              api.VirtualStorage
	temporaryFolder string
}

func (s *svc) RestoreRevision(ctx context.Context, req *api.RevisionReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.vs.RestoreRevision(ctx, req.Path, req.RevKey); err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) UpdateACL(ctx context.Context, req *api.ACLReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	err := s.vs.UpdateACL(ctx, req.Path, req.ReadOnly, req.Recipient, req.Shares)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) SetACL(ctx context.Context, req *api.ACLReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	err := s.vs.SetACL(ctx, req.Path, req.ReadOnly, req.Recipient, req.Shares)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) UnsetACL(ctx context.Context, req *api.ACLReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	err := s.vs.UnsetACL(ctx, req.Path, req.Recipient, req.Shares)
	if err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) RestoreRecycleEntry(ctx context.Context, req *api.RecycleEntryReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.vs.RestoreRecycleEntry(ctx, req.RestoreKey); err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) ReadRevision(req *api.RevisionReq, stream api.Storage_ReadRevisionServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	readCloser, err := s.vs.DownloadRevision(ctx, req.Path, req.RevKey)
	defer func() {
		l.Debug("closing fd when reading version for path: " + req.Path)
		if err := readCloser.Close(); err != nil {
			l.Error("error closing fd", zap.Error(err))
		}
	}()
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}

	bufferedReader := bufio.NewReaderSize(readCloser, 1024*1024*3)

	// send data chunks of maximum 1 MiB
	buffer := make([]byte, 1024*1024*3)
	for {
		n, err := bufferedReader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			l.Error("", zap.Error(err))
			return err
		}
		dc := &api.DataChunk{Data: buffer, Length: uint64(n)}
		dcRes := &api.DataChunkResponse{DataChunk: dc}
		if err := stream.Send(dcRes); err != nil {
			l.Error("", zap.Error(err))
			return nil
		}
	}
	return nil
}

func (s *svc) ReadFile(req *api.PathReq, stream api.Storage_ReadFileServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	readCloser, err := s.vs.Download(ctx, req.Path)
	if err != nil {
		l.Error("error reading file from fs", zap.Error(err))
		return err
	}
	defer func() {
		l.Debug("closing fd when reading for path: " + req.Path)
		if err := readCloser.Close(); err != nil {
			l.Error("error closing fd", zap.Error(err))
		}
	}()

	// send data chunks of maximum 3 MiB
	buffer := make([]byte, 1024*1024*3)
	for {
		n, err := readCloser.Read(buffer)
		if n > 0 {
			dc := &api.DataChunk{Data: buffer[:n], Length: uint64(n)}
			dcRes := &api.DataChunkResponse{DataChunk: dc}
			if err := stream.Send(dcRes); err != nil {
				l.Error("", zap.Error(err))
				return nil
			}

		}
		if err == io.EOF {
			break

		}
		if err != nil {
			l.Error("error when reading from readcloser", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) ListRevisions(req *api.PathReq, stream api.Storage_ListRevisionsServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	revs, err := s.vs.ListRevisions(ctx, req.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}
	for _, rev := range revs {
		revRes := &api.RevisionResponse{Revision: rev}
		if err := stream.Send(revRes); err != nil {
			l.Error("", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) ListRecycle(req *api.PathReq, stream api.Storage_ListRecycleServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	entries, err := s.vs.ListRecycle(ctx, req.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		return err
	}
	for _, e := range entries {
		recycleEntryRes := &api.RecycleEntryResponse{RecycleEntry: e}
		if err := stream.Send(recycleEntryRes); err != nil {
			l.Error("", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) ListFolder(req *api.PathReq, stream api.Storage_ListFolderServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	mds, err := s.vs.ListFolder(ctx, req.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		status := api.GetStatus(err)
		mdRes := &api.MetadataResponse{Status: status}
		if err := stream.Send(mdRes); err != nil {
			return err
		}
		return nil
	}
	for _, md := range mds {
		mdRes := &api.MetadataResponse{Metadata: md}
		if err := stream.Send(mdRes); err != nil {
			l.Error("", zap.Error(err))
			return err
		}
	}
	return nil
}

func (s *svc) GetQuota(ctx context.Context, req *api.QuotaReq) (*api.QuotaResponse, error) {
	l := ctx_zap.Extract(ctx)
	total, used, err := s.vs.GetQuota(ctx, req.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		status := api.GetStatus(err)
		quotaRes := &api.QuotaResponse{Status: status}
		return quotaRes, nil
	}
	return &api.QuotaResponse{TotalBytes: int64(total), UsedBytes: int64(used)}, nil

}

func (s *svc) CreateDir(ctx context.Context, req *api.PathReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.vs.CreateDir(ctx, req.Path); err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) Delete(ctx context.Context, req *api.PathReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.vs.Delete(ctx, req.Path); err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) Inspect(ctx context.Context, req *api.PathReq) (*api.MetadataResponse, error) {
	l := ctx_zap.Extract(ctx)
	md, err := s.vs.GetMetadata(ctx, req.Path)
	if err != nil {
		l.Error("", zap.Error(err))
		status := api.GetStatus(err)
		mdRes := &api.MetadataResponse{Status: status}
		return mdRes, nil
	}
	mdRes := &api.MetadataResponse{Metadata: md}
	return mdRes, nil
}

func (s *svc) EmptyRecycle(ctx context.Context, req *api.PathReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.vs.EmptyRecycle(ctx, req.Path); err != nil {
		l.Error("", zap.Error(err))
		status := api.GetStatus(err)
		return &api.EmptyResponse{Status: status}, nil
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) WriteChunk(stream api.Storage_WriteChunkServer) error {
	ctx := stream.Context()
	l := ctx_zap.Extract(ctx)
	numChunks := uint64(0)
	totalSize := uint64(0)
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			l.Error("", zap.Error(err))
			return err
		}
		txFolder := s.getTxFolder(req.TxId)
		if _, err := os.Stat(txFolder); err != nil {
			l.Error("", zap.Error(err))
			return err
		}

		chunkFile := filepath.Join(txFolder, fmt.Sprintf("%d-%d", req.Offset, req.Length))
		fd, err := os.OpenFile(chunkFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
		defer fd.Close()
		if err != nil {
			l.Error("", zap.Error(err))
			return err
		}
		reader := bytes.NewReader(req.Data)
		n, err := io.CopyN(fd, reader, int64(req.Length))
		if err != nil {
			l.Error("", zap.Error(err))
			return err
		}
		numChunks++
		totalSize += uint64(n)
		fd.Close()
	}

	writeSummary := &api.WriteSummary{Nchunks: numChunks, TotalSize: totalSize}
	writeSummaryRes := &api.WriteSummaryResponse{WriteSummary: writeSummary}
	return stream.SendAndClose(writeSummaryRes)
}

func (s *svc) StartWriteTx(ctx context.Context, req *api.EmptyReq) (*api.TxInfoResponse, error) {
	l := ctx_zap.Extract(ctx)
	// create a temporary folder with the TX ID
	uuid := uuid.Must(uuid.NewV4())
	txID := uuid.String()
	txFolder := s.getTxFolder(txID)
	if err := os.Mkdir(txFolder, 0755); err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	txInfo := &api.TxInfo{TxId: txID}
	txInfoRes := &api.TxInfoResponse{TxInfo: txInfo}
	return txInfoRes, nil
}

type chunkInfo struct {
	Offset       uint64
	ClientLength uint64
}

func parseChunkFilename(fn string) (*chunkInfo, error) {
	parts := strings.Split(fn, "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("chunk filename is wrong: %s", fn)
	}

	offset, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return nil, err
	}
	clientLength, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, err
	}
	return &chunkInfo{Offset: offset, ClientLength: clientLength}, nil
}

func (s *svc) getSortedChunkSlice(names []string) []string {
	// sort names numerically by chunk
	sort.Slice(names, func(i, j int) bool {
		previous := names[i]
		next := names[j]

		previousOffset, err := strconv.ParseInt(strings.Split(previous, "-")[0], 10, 64)
		if err != nil {
			panic("chunk name cannot be casted to int: " + previous)
		}
		nextOffset, err := strconv.ParseInt(strings.Split(next, "-")[0], 10, 64)
		if err != nil {
			panic("chunk name cannot be casted to int: " + next)
		}
		return previousOffset < nextOffset
	})
	return names
}

func (s *svc) FinishWriteTx(ctx context.Context, req *api.TxEnd) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	txFolder := s.getTxFolder(req.TxId)
	fd, err := os.Open(txFolder)
	defer fd.Close()
	if os.IsNotExist(err) {
		return nil, err
	}
	defer os.RemoveAll(txFolder) // remove txFolder once assembled file is returned

	// list all the chunks in the directory
	names, err := fd.Readdirnames(0)
	if err != nil {
		return &api.EmptyResponse{}, err
	}

	names = s.getSortedChunkSlice(names)

	l.Debug("chunk sorted names", zap.String("names", fmt.Sprintf("%+v", names)))
	l.Info("number of chunks", zap.String("nchunks", fmt.Sprintf("%d", len(names))))

	uuid := uuid.Must(uuid.NewV4())
	rand := uuid.String()
	assembledFilename := filepath.Join(txFolder, fmt.Sprintf("assembled-%s", rand))
	l.Info("", zap.String("assembledfilename", assembledFilename))

	assembledFile, err := os.OpenFile(assembledFilename, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}

	for i, n := range names {
		l.Debug("processing chunk", zap.String("name", n), zap.Int("int", i))
		chunkFilename := filepath.Join(txFolder, n)
		l.Info(fmt.Sprintf("processing chunk %d", i), zap.String("chunk", chunkFilename))

		chunkInfo, err := parseChunkFilename(filepath.Base(chunkFilename))
		if err != nil {
			return &api.EmptyResponse{}, err
		}
		chunk, err := os.Open(chunkFilename)
		defer chunk.Close()
		if err != nil {
			return nil, err
		}
		n, err := io.CopyN(assembledFile, chunk, int64(chunkInfo.ClientLength))
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n != int64(chunkInfo.ClientLength) {
			return nil, fmt.Errorf("chunk size in disk is different from chunk size sent from client. Read: %d Sent: %d", n, chunkInfo.ClientLength)
		}
		chunk.Close()
	}
	assembledFile.Close()

	fd, err = os.Open(assembledFilename)
	if err != nil {
		l.Error("")
		return nil, err
	}

	if err := s.vs.Upload(ctx, req.Path, fd); err != nil {
		return nil, err
	}

	return &api.EmptyResponse{}, nil
}

func (s *svc) Move(ctx context.Context, req *api.MoveReq) (*api.EmptyResponse, error) {
	l := ctx_zap.Extract(ctx)
	if err := s.vs.Move(ctx, req.OldPath, req.NewPath); err != nil {
		l.Error("", zap.Error(err))
		return nil, err
	}
	return &api.EmptyResponse{}, nil
}

func (s *svc) getTxFolder(txID string) string {
	return filepath.Join(s.temporaryFolder, txID)
}
