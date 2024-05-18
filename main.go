package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type config struct {
	origin string
}

func main() {
	port := "7835"

	fmt.Printf("starting fake oidc server on :%s\n", port)

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	origin := fmt.Sprintf("http://localhost:%s", port)
	config := config{origin}
	storage := newStorage(config)
	provider, err := newProvider(config, storage)
	if err != nil {
		slog.Error("failed to build provider: %w", err)
		os.Exit(1)
		return
	}

	r.Mount("/", provider.Handler)

	r.Get("/login", loginForm())
	r.Post("/login", loginPost(storage, op.NewIssuerInterceptor(provider.IssuerFromRequest), op.AuthCallbackURL(provider)))

	http.ListenAndServe(":"+port, r)
}

func newProvider(appConfig config, s *inmemStorage) (*op.Provider, error) {
	config := op.Config{
		CryptoKey:             sha256.Sum256([]byte("fake-oidc-key")),
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedClaims:       []string{"openid", "access"},
	}
	provider, err := op.NewProvider(
		&config,
		s,
		op.StaticIssuer(appConfig.origin),
		op.WithAllowInsecure(),
	)

	return provider, err
}

// login page things

var (
	//go:embed templates
	fs        embed.FS
	templates = template.Must(template.ParseFS(fs, "templates/*.html"))
)

func loginForm() func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		authRequestID := r.FormValue("authRequestID")

		data := &struct {
			ID      string
			Message string
		}{ID: authRequestID, Message: ""}
		err := templates.ExecuteTemplate(w, "login", data)
		if err != nil {
			slog.Error("html error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func loginPost(s *inmemStorage, issuerIntercepter *op.IssuerInterceptor, buildCallbackURL func(context.Context, string) string) func(w http.ResponseWriter, r *http.Request) {

	return issuerIntercepter.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		authRequestID := r.FormValue("id")

		if len(username) == 0 {
			slog.Error("username too short")
			w.WriteHeader(http.StatusBadRequest)
		}

		s.lock.Lock()
		defer s.lock.Unlock()

		var existingUser *user
		for _, v := range s.users {
			if v.username == username {
				existingUser = v
			}
		}

		if existingUser == nil {
			user := user{
				id:       uuid.NewString(),
				name:     strings.ToUpper(username[:1]) + username[1:],
				username: username,
			}
			s.users[user.id] = &user
			existingUser = &user
		}

		s.authRequests[authRequestID].subject = existingUser.id
		s.authRequests[authRequestID].done = true

		callbackURL := buildCallbackURL(r.Context(), authRequestID)
		http.Redirect(w, r, callbackURL, http.StatusTemporaryRedirect)
	})
}
