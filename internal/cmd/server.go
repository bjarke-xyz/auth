package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	firebase "firebase.google.com/go/v4"
	"github.com/bjarke-xyz/auth/internal/cmdutil"
	serverPkg "github.com/bjarke-xyz/auth/internal/server"
	"github.com/bjarke-xyz/auth/internal/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"
)

func ServerCmd(ctx context.Context) *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "server",
		Args:  cobra.ExactArgs(0),
		Short: "Runs the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			port = 7100
			grpcPort := 7101
			if os.Getenv("PORT") != "" {
				port, _ = strconv.Atoi(os.Getenv("PORT"))
			}
			if os.Getenv("GRPC_PORT") != "" {
				grpcPort, _ = strconv.Atoi(os.Getenv("GRPC_PORT"))
			}
			logger := cmdutil.NewLogger("api")

			credentialsJson := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS_CONTENT")
			credentialsJsonBytes := []byte(credentialsJson)
			opt := option.WithCredentialsJSON(credentialsJsonBytes)
			app, err := firebase.NewApp(ctx, nil, opt)
			if err != nil {
				return fmt.Errorf("error initializing app: %w", err)
			}

			allowedUsersJson := os.Getenv("ALLOWED_USERS")
			allowedUsersJsonBytes := []byte(allowedUsersJson)
			allowedUsers := make([]string, 0)
			err = json.Unmarshal(allowedUsersJsonBytes, &allowedUsers)
			if err != nil {
				return fmt.Errorf("error unmarshaling ALLOWED_USERS environment variable")
			}

			authClient := service.NewFirebaseAuthRestClient(os.Getenv("FIREBASE_WEB_API_KEY"), os.Getenv("FIREBASE_PROJECT_ID"))

			server, err := serverPkg.NewServer(ctx, logger, app, authClient, allowedUsers)
			if err != nil {
				return fmt.Errorf("error initializing server: %w", err)
			}
			srv := server.Server(port)
			grpcSrv, grpcLis, err := server.GrpcServer(grpcPort)
			if err != nil {
				return fmt.Errorf("failed to create grpc server: %w", err)
			}

			// metrics server
			go func() {
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				http.ListenAndServe(":9091", mux)
			}()

			go func() {
				_ = srv.ListenAndServe()
			}()
			go func() {
				_ = grpcSrv.Serve(grpcLis)
			}()
			logger.Info("started server", "webPort", port, "grpcPort", grpcPort)
			<-ctx.Done()
			_ = srv.Shutdown(ctx)
			return nil
		},
	}
	return cmd
}
