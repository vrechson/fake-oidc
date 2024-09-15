package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Server struct {
	sv *http.Server
	ln net.Listener

	port string
}

type config struct {
	origin    string
	shouldLog bool
}

// Creates a new fake-oidc on the specified port.
// If the port is 0, the server will bind an available port.
// The port should not be prefixed with a colon.
func NewServer(port string, shouldLog bool) (*Server, error) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("could not bind port: %w", err)
	}

	config := config{origin: "http://" + ln.Addr().String(), shouldLog: shouldLog}

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
		return nil, fmt.Errorf("could not build provider: %w", err)
	}

	r.Mount("/", provider.Handler)

	interceptor := op.NewIssuerInterceptor(provider.IssuerFromRequest)
	r.Get("/login", interceptor.HandlerFunc(loginForm(storage, op.AuthCallbackURL(provider))))
	r.Post("/login", interceptor.HandlerFunc(loginPost(storage, op.AuthCallbackURL(provider))))

	server := &Server{
		port: port,
		ln:   ln,
		sv: &http.Server{
			Handler: r,
		},
	}

	return server, nil
}

// Begins running the HTTP server. You probably want to call this in a Goroutine.
func (s *Server) Open() error {
	return s.sv.Serve(s.ln)
}

// Closes the HTTP server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()
	return s.sv.Shutdown(ctx)
}

// Returns the address the server is running on.
// Useful if you've bound a random port.
func (s *Server) GetBoundAddr() string {
	return s.ln.Addr().String()
}

func newProvider(appConfig config, s *inmemStorage) (*op.Provider, error) {
	config := op.Config{
		CryptoKey:             sha256.Sum256([]byte("fake-oidc-key")),
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedClaims:       []string{},
	}

	args := []op.Option{
		op.WithAllowInsecure(),
	}

	if !appConfig.shouldLog {
		args = append(args, op.WithLogger(slog.New(slog.NewJSONHandler(io.Discard, nil))))
	}

	provider, err := op.NewProvider(
		&config,
		s,
		op.StaticIssuer(appConfig.origin),
		args...,
	)

	return provider, err
}
