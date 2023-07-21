package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/bjarke-xyz/auth/internal/server/html"
	"github.com/bjarke-xyz/auth/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/exp/slog"
	"google.golang.org/api/iterator"
)

//go:embed static
var staticFiles embed.FS

type server struct {
	logger *slog.Logger

	app        *firebase.App
	authClient *service.FirebaseAuthRestClient

	allowedUsers []string

	staticFilesFs fs.FS
}

func NewServer(ctx context.Context, logger *slog.Logger, app *firebase.App, authClient *service.FirebaseAuthRestClient, allowedUsers []string) (*server, error) {
	staticFilesFs, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	return &server{
		logger:        logger,
		app:           app,
		authClient:    authClient,
		allowedUsers:  allowedUsers,
		staticFilesFs: staticFilesFs,
	}, nil
}
func (s *server) Server(port int) *http.Server {
	return &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: s.Routes(),
	}
}

func (s *server) Routes() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(s.staticFilesFs))))
	r.Handle("/favicon.ico", http.FileServer(http.FS(s.staticFilesFs)))

	r.Get("/up", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "up!")
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		err := r.URL.Query().Get("error")
		html.IndexPage(w, html.IndexParams{Title: "index siden", Error: err})
	})

	r.Post("/login", s.handleLogin)
	r.Post("/logout", s.handleLogout)

	r.Route("/admin", func(r chi.Router) {
		r.Use(s.firebaseJwtVerifier)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			// token, _, _ := TokenFromContext(r.Context())
			firebaseAuth, _ := s.app.Auth(r.Context())
			userIterator := firebaseAuth.Users(r.Context(), "")
			users := make([]*auth.UserRecord, 0)
			for {
				user, err := userIterator.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					s.logger.Error("error getting user", "error", err)
					break
				}
				users = append(users, user.UserRecord)
			}
			sort.Slice(users, func(i, j int) bool {
				return users[i].UserMetadata.CreationTimestamp < users[j].UserMetadata.CreationTimestamp
			})
			p := html.AdminParams{
				Title: "Admin",
				Users: users,
			}
			html.AdminPage(w, p)
		})

		r.Get("/user", func(w http.ResponseWriter, r *http.Request) {
			errMsg := r.URL.Query().Get("error")
			if errMsg != "" {
				p := html.UserParams{
					Title: "User",
					Error: errMsg,
				}
				html.UserPage(w, p)
				return
			}
			uid := r.URL.Query().Get("uid")
			if uid == "" {
				p := html.UserParams{
					Title: "User",
					Error: "No uid",
				}
				html.UserPage(w, p)
				return
			}
			firebaseAuth, err := s.app.Auth(r.Context())
			if err != nil {
				s.logger.Error("error getting auth", "error", err)
				p := html.UserParams{
					Title: "User",
					Error: err.Error(),
				}
				html.UserPage(w, p)
				return
			}
			user, err := firebaseAuth.GetUser(r.Context(), uid)
			if err != nil {
				s.logger.Error("error getting user", "error", err)
				p := html.UserParams{
					Title: "User",
					Error: err.Error(),
				}
				html.UserPage(w, p)
				return
			}
			customClaimsJson := ""
			if len(user.CustomClaims) > 0 {
				customClaimsJsonBytes, err := json.Marshal(user.CustomClaims)
				if err != nil {
					s.logger.Error("error marshaling custom claims", "error", err)
					p := html.UserParams{
						Title: "User",
						Error: err.Error(),
					}
					html.UserPage(w, p)
					return
				}
				customClaimsJson = string(customClaimsJsonBytes)
			}

			p := html.UserParams{
				Title:                "User",
				User:                 user,
				UserCustomClaimsJson: customClaimsJson,
			}
			html.UserPage(w, p)
		})

		r.Post("/user", func(w http.ResponseWriter, r *http.Request) {
			uid := r.FormValue("uid")
			if uid == "" {
				http.Redirect(w, r, fmt.Sprintf("/admin/user?uid=%v&error=missing uid", uid), http.StatusSeeOther)
				return
			}
			firebaseAuth, err := s.app.Auth(r.Context())
			if err != nil {
				s.logger.Error("error getting auth", "error", err)
				http.Redirect(w, r, fmt.Sprintf("/admin/user?uid=%v&rror=%v", uid, err), http.StatusSeeOther)
				return
			}
			user, err := firebaseAuth.GetUser(r.Context(), uid)
			if err != nil {
				s.logger.Error("error getting user", "error", err)
				http.Redirect(w, r, fmt.Sprintf("/admin/user?uid=%v&error=%v", uid, err), http.StatusSeeOther)
				return
			}
			customClaimsJson := r.FormValue("customClaims")
			if customClaimsJson == "" {
				// Create empty JSON object, if user attempts to save empty string
				customClaimsJson = "{}"
			}
			customClaimsJsonBytes := []byte(customClaimsJson)
			customClaims := make(map[string]interface{})
			err = json.Unmarshal(customClaimsJsonBytes, &customClaims)
			if err != nil {
				s.logger.Error("failed to unmarshal custom claims", "error", err)
				http.Redirect(w, r, fmt.Sprintf("/admin/user?uid=%v&error=%v", user.UID, err), http.StatusSeeOther)
				return
			}

			err = firebaseAuth.SetCustomUserClaims(r.Context(), user.UID, customClaims)
			if err != nil {
				s.logger.Error("failed to set ustom claims", "error", err)
				http.Redirect(w, r, fmt.Sprintf("/admin/user?uid=%v&error=%v", user.UID, err), http.StatusSeeOther)
				return
			}

			http.Redirect(w, r, fmt.Sprintf("/admin/user?uid=%v", user.UID), http.StatusSeeOther)
		})
	})

	return r
}
