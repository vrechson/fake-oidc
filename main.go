package main

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type config struct {
	origin string
	port   string
}

func main() {
	config := newConfig()

	fmt.Printf("starting fake oidc server on :%s\n", config.port)

	r := chi.NewRouter()

	r.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// signing keys will change if restarted, so tell clients to never cache responses
			w.Header().Add("cache-control", "no-store, no-store, must-revalidate")
			w.Header().Add("pragma", "no-cache")
			w.Header().Add("expires", "0")
			h.ServeHTTP(w, r)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	storage := newStorage(config)
	provider, err := newProvider(config, storage)
	if err != nil {
		slog.Error("failed to build provider: %w", err)
		os.Exit(1)
		return
	}

	r.Mount("/", provider.Handler)

	interceptor := op.NewIssuerInterceptor(provider.IssuerFromRequest)
	r.Get("/login", interceptor.HandlerFunc(loginForm(storage, op.AuthCallbackURL(provider))))
	r.Post("/login", interceptor.HandlerFunc(loginPost(storage, op.AuthCallbackURL(provider))))

	http.ListenAndServe(":"+config.port, r)
}

func newProvider(appConfig config, s *inmemStorage) (*op.Provider, error) {
	config := op.Config{
		CryptoKey:             sha256.Sum256([]byte("fake-oidc-key")),
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedClaims:       []string{},
	}
	provider, err := op.NewProvider(
		&config,
		s,
		op.StaticIssuer(appConfig.origin),
		op.WithAllowInsecure(),
	)

	return provider, err
}

func newConfig() config {
	port := os.Getenv("FAKE_OIDC_HTTP_PORT")
	if len(port) == 0 {
		port = "7835"
	}

	return config{
		port:   port,
		origin: fmt.Sprintf("http://localhost:%s", port),
	}
}
