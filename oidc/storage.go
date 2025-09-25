package oidc

import (
	"context"
	"sync"
)

type inmemStorage struct {
	config    config
	appConfig *Config
	client    clientWithRedirectGlobs

	signingKey *signingKey

	// below are locked by mutex
	lock sync.Mutex

	authRequests         map[string]*authRequest // request id => request
	authCodes            map[string]string       // auth code => request id
	users                map[string]*user
	tokens               map[string]*accessToken
	refreshTokensByToken map[string]*refreshToken
	refreshTokensByID    map[string]*refreshToken
}

func newStorage(config config, appConfig *Config) *inmemStorage {
	return &inmemStorage{
		config:    config,
		appConfig: appConfig,
		client:    newClient(config, appConfig),

		signingKey: makeAKey(),

		lock:                 sync.Mutex{},
		authRequests:         map[string]*authRequest{},
		authCodes:            map[string]string{},
		users:                map[string]*user{},
		tokens:               map[string]*accessToken{},
		refreshTokensByID:    map[string]*refreshToken{},
		refreshTokensByToken: map[string]*refreshToken{},
	}
}

func (s *inmemStorage) Health(ctx context.Context) error {
	return nil
}
