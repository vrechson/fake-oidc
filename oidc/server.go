package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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

	port     string
	tls      bool
	certFile string
	keyFile  string
}

type config struct {
	origin    string
	shouldLog bool
}

// Creates a new fake-oidc on the specified port.
// If the port is 0, the server will bind an available port.
// The port should not be prefixed with a colon.
func NewServer(host string, port string, shouldLog bool) (*Server, error) {
	// Load configuration
	appConfig, err := LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}

	// Override config with command line parameters if provided
	if host != "" {
		appConfig.Server.Host = host
	}
	if port != "" {
		appConfig.Server.Port = port
	}
	appConfig.Features.EnableLogging = shouldLog

	// Set issuer URL based on server configuration
	appConfig.Issuer.URL = appConfig.GetIssuerURL()

	ln, err := net.Listen("tcp", appConfig.GetServerAddress())
	if err != nil {
		return nil, fmt.Errorf("could not bind port: %w", err)
	}

	config := config{origin: appConfig.GetIssuerURL(), shouldLog: shouldLog}

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

	storage := newStorage(config, appConfig)
	provider, err := newProvider(config, storage, appConfig)
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
		tls:  false, // Legacy server doesn't support TLS
		sv: &http.Server{
			Handler: r,
		},
	}

	return server, nil
}

// NewServerWithConfig creates a new fake-oidc server using the provided configuration
func NewServerWithConfig(appConfig *Config) (*Server, error) {
	// Set issuer URL based on server configuration
	appConfig.Issuer.URL = appConfig.GetIssuerURL()

	ln, err := net.Listen("tcp", appConfig.GetServerAddress())
	if err != nil {
		return nil, fmt.Errorf("could not bind port: %w", err)
	}

	config := config{origin: appConfig.GetIssuerURL(), shouldLog: appConfig.Features.EnableLogging}

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

	storage := newStorage(config, appConfig)
	provider, err := newProvider(config, storage, appConfig)
	if err != nil {
		return nil, fmt.Errorf("could not build provider: %w", err)
	}

	r.Mount("/", provider.Handler)

	interceptor := op.NewIssuerInterceptor(provider.IssuerFromRequest)
	r.Get("/login", interceptor.HandlerFunc(loginForm(storage, op.AuthCallbackURL(provider))))
	r.Post("/login", interceptor.HandlerFunc(loginPost(storage, op.AuthCallbackURL(provider))))

	server := &Server{
		port:     appConfig.Server.Port,
		ln:       ln,
		tls:      appConfig.Server.TLS.Enabled,
		certFile: appConfig.Server.TLS.CertFile,
		keyFile:  appConfig.Server.TLS.KeyFile,
		sv: &http.Server{
			Handler: r,
		},
	}

	// Configure TLS if enabled
	if appConfig.Server.TLS.Enabled {
		if appConfig.Server.TLS.CertFile == "" || appConfig.Server.TLS.KeyFile == "" {
			return nil, fmt.Errorf("TLS enabled but cert_file or key_file not specified")
		}
		server.sv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return server, nil
}

// Begins running the HTTP server. You probably want to call this in a Goroutine.
func (s *Server) Open() error {
	if s.tls {
		return s.sv.ServeTLS(s.ln, s.certFile, s.keyFile)
	}
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

func newProvider(appConfig config, s *inmemStorage, cfg *Config) (*op.Provider, error) {
	config := op.Config{
		CryptoKey:             sha256.Sum256([]byte("fake-oidc-key")),
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedClaims:       cfg.Features.SupportedClaims,
	}

	args := []op.Option{}

	if cfg.Features.AllowInsecure {
		args = append(args, op.WithAllowInsecure())
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
