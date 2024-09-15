package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func (s *inmemStorage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	authRequest := &AuthRequest{
		id: uuid.New().String(),

		audience: req.ClientID,
		authTime: time.Now(),
		clientID: req.ClientID,

		codeChallenge: &oidc.CodeChallenge{
			Challenge: req.CodeChallenge,
			Method:    req.CodeChallengeMethod,
		},

		nonce:        req.Nonce,
		redirectURI:  req.RedirectURI,
		responseType: req.ResponseType,
		responseMode: req.ResponseMode,

		scopes:  req.Scopes,
		state:   req.State,
		subject: userID,
		done:    false,
	}

	s.authRequests[authRequest.id] = authRequest

	return authRequest, nil
}
func (s *inmemStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if ar, ok := s.authRequests[id]; ok {
		return ar, nil
	}

	return nil, errors.New("auth request not found")
}

func (s *inmemStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if requestID, ok := s.authCodes[code]; ok {
		return s.authRequests[requestID], nil
	}

	return nil, errors.New("auth code not found")
}

func (s *inmemStorage) SaveAuthCode(ctx context.Context, requestID string, code string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.authCodes[code] = requestID

	return nil
}

func (s *inmemStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.authRequests, id)

	// also clear references to request in authCodes
	for k, v := range s.authCodes {
		if v == id {
			delete(s.authCodes, k)
		}
	}

	return nil
}

// The TokenRequest parameter of CreateAccessToken can be any of:
//
// * TokenRequest as returned by ClientCredentialsStorage.ClientCredentialsTokenRequest,
//
// * AuthRequest as returned by AuthRequestByID or AuthRequestByCode (above)
//
//   - *oidc.JWTTokenRequest from a JWT that is the assertion value of a JWT Profile
//     Grant: https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
//
// * TokenExchangeRequest as returned by ValidateTokenExchangeRequest
func (s *inmemStorage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (accessTokenID string, expiration time.Time, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	token := s.newAccessToken(s.client.id, "", req.GetSubject(), req.GetScopes(), req.GetAudience())

	return token.id, token.expiresAt, nil
}

// The TokenRequest parameter of CreateAccessAndRefreshTokens can be any of:
//
// * TokenRequest as returned by ClientCredentialsStorage.ClientCredentialsTokenRequest
//
// * RefreshTokenRequest as returned by AuthStorage.TokenRequestByRefreshToken
//
//   - AuthRequest as by returned by the AuthRequestByID or AuthRequestByCode (above).
//     Used for the authorization code flow which requested offline_access scope and
//     registered the refresh_token grant type in advance
//
// * TokenExchangeRequest as returned by ValidateTokenExchangeRequest
func (s *inmemStorage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if currentRefreshToken == "" {
		refreshToken := s.newRefreshToken(s.client.id, req.GetSubject(), req.GetScopes(), req.GetAudience())
		token := s.newAccessToken(s.client.id, refreshToken.id, req.GetSubject(), req.GetScopes(), req.GetAudience())

		return token.id, refreshToken.token, token.expiresAt, nil
	}

	// find existing
	curToken, ok := s.refreshTokensByToken[currentRefreshToken]
	if !ok {
		return "", "", time.Time{}, errors.New("refresh token not found")
	}

	// remove existing refresh and access tokens
	delete(s.refreshTokensByID, curToken.id)
	delete(s.refreshTokensByToken, curToken.token)
	for k, v := range s.tokens {
		if v.refreshTokenID == curToken.id {
			delete(s.tokens, k)
		}
	}

	// renew refresh token
	curToken.id = uuid.NewString()
	curToken.token = base64.URLEncoding.EncodeToString([]byte(uuid.NewString()))
	s.refreshTokensByID[curToken.id] = curToken
	s.refreshTokensByToken[curToken.token] = curToken

	token := s.newAccessToken(s.client.id, curToken.id, req.GetSubject(), req.GetScopes(), req.GetAudience())

	return token.id, curToken.token, token.expiresAt, nil
}

func (s *inmemStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	rt, ok := s.refreshTokensByToken[refreshToken]
	if !ok {
		return nil, fmt.Errorf("could not find refresh token : %s", refreshToken)
	}

	return &refreshTokenRequest{rt}, nil
}

func (s *inmemStorage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	for k, v := range s.tokens {
		if v.subject == userID && v.clientID == clientID {
			delete(s.tokens, k)
		}
	}

	for k, v := range s.refreshTokensByID {
		if v.subject == userID && v.clientID == clientID {
			delete(s.refreshTokensByID, k)
			delete(s.refreshTokensByToken, v.token)
		}
	}

	return nil
}

// RevokeToken should revoke a token. In the situation that the original request was to
// revoke an access token, then tokenOrTokenID will be a tokenID and userID will be set
// but if the original request was for a refresh token, then userID will be empty and
// tokenOrTokenID will be the refresh token, not its ID.  RevokeToken depends upon GetRefreshTokenInfo
// to get information from refresh tokens that are not either "<tokenID>:<userID>" strings
// nor JWTs.
func (s *inmemStorage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// try looking up by id (access token)
	accessToken, ok := s.tokens[tokenOrTokenID]
	if ok {
		if accessToken.subject != userID {
			return oidc.ErrInvalidRequest().WithDescription("wrong subject for revoke")
		}
		if accessToken.clientID != clientID {
			return oidc.ErrInvalidRequest().WithDescription("wrong client for revoke")
		}

		delete(s.tokens, accessToken.id)

		return nil
	}

	// try looking up by token (refresh token)
	refreshToken, ok := s.refreshTokensByToken[tokenOrTokenID]
	if ok {
		if refreshToken.subject != userID {
			return oidc.ErrInvalidRequest().WithDescription("wrong subject for revoke")
		}
		if refreshToken.clientID != clientID {
			return oidc.ErrInvalidRequest().WithDescription("wrong client for revoke")
		}

		delete(s.refreshTokensByID, refreshToken.id)
		delete(s.refreshTokensByToken, refreshToken.token)
		for k, v := range s.tokens {
			if v.refreshTokenID == refreshToken.id {
				delete(s.tokens, k)
			}
		}
	}

	// otherwise the token or id doesn't exist
	return nil
}

// GetRefreshTokenInfo must return ErrInvalidRefreshToken when presented
// with a token that is not a refresh token.
func (s *inmemStorage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	refreshToken, ok := s.refreshTokensByToken[token]
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}

	if refreshToken.clientID != clientID {
		return "", "", errors.New("invalid client id to get refresh token info")
	}

	return refreshToken.subject, refreshToken.id, nil
}

func (s *inmemStorage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.signingKey, nil
}

func (s *inmemStorage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.SignatureAlgorithm()}, nil
}

func (s *inmemStorage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{internal: *s.signingKey}}, nil
}

// helpers

func (s *inmemStorage) newAccessToken(clientID string, refreshTokenID string, subject string, scopes []string, audience []string) *accessToken {
	token := &accessToken{
		id:             uuid.NewString(),
		clientID:       clientID,
		subject:        subject,
		scopes:         scopes,
		audience:       audience,
		expiresAt:      time.Now().Add(time.Duration(900 * time.Second)),
		refreshTokenID: refreshTokenID,
	}
	s.tokens[token.id] = token

	return token
}

func (s *inmemStorage) newRefreshToken(clientID string, subject string, scopes []string, audience []string) *refreshToken {
	token := &refreshToken{
		id:    uuid.NewString(),
		token: base64.URLEncoding.EncodeToString([]byte(uuid.NewString())),

		clientID:  clientID,
		subject:   subject,
		scopes:    scopes,
		audience:  audience,
		expiresAt: time.Now().Add(time.Duration(28800 * time.Second)),

		authTime: time.Now(),
		amr:      []string{},
	}
	s.refreshTokensByToken[token.token] = token
	s.refreshTokensByID[token.id] = token

	return token
}
