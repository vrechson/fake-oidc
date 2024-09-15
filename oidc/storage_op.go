package oidc

import (
	"context"
	"errors"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func (s *inmemStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	if s.client.id == clientID {
		return &s.client, nil
	}

	return nil, errors.New("client not found")
}

func (s *inmemStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	if s.client.id != clientID {
		return errors.New("client not found")
	}

	if s.client.secret != clientSecret {
		return errors.New("invalid client secret")
	}

	return nil
}

func (s *inmemStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	// DEPRECATED - do not implement
	return nil
}

func (s *inmemStorage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	user, ok := s.users[request.GetSubject()]
	if !ok {
		return errors.New("user not found")
	}

	userinfo.Subject = user.id
	userinfo.Name = user.name
	userinfo.Email = user.username + "@idm.local"

	return nil
}

func (s *inmemStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return errors.New("token not found")
	}

	userinfo.Subject = token.subject
	userinfo.Name = s.users[token.subject].name
	userinfo.Email = s.users[token.subject].username + "@idm.local"

	return nil
}

func (s *inmemStorage) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return errors.New("token not found")
	}

	userinfo.Subject = token.subject
	userinfo.Name = s.users[token.subject].name
	userinfo.Email = s.users[token.subject].username + "@idm.local"

	return nil
}

func (s *inmemStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *inmemStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	if keyID != s.signingKey.ID() {
		return nil, errors.New("key not found")
	}
	return &jose.JSONWebKey{
		KeyID: keyID,
		Use:   "sig",
		Key:   s.signingKey.key.PublicKey,
	}, nil
}

func (s *inmemStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}
