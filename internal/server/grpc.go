package server

import (
	"context"
	"errors"
	"os"

	"github.com/bjarke-xyz/auth/internal/auth"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authServer struct {
	auth.UnimplementedAuthServer
	logger *slog.Logger
}

func (s *authServer) ValidateToken(ctx context.Context, req *auth.ValidateTokenRequest) (*auth.AuthToken, error) {
	audience := req.Audience
	if audience == "" {
		audience = os.Getenv("FIREBASE_PROJECT_ID")
	}
	authToken, err := auth.ValidateToken(ctx, audience, req.Token)
	if errors.Is(err, auth.ErrValidation) {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return authToken, err
}

func newAuthServer(logger *slog.Logger) *authServer {
	s := &authServer{
		logger: logger,
	}
	return s
}
