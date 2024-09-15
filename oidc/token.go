package oidc

import "time"

type accessToken struct {
	id        string
	clientID  string
	subject   string
	audience  []string
	expiresAt time.Time
	scopes    []string

	refreshTokenID string
}

type refreshToken struct {
	id        string
	clientID  string
	token     string
	subject   string
	audience  []string
	expiresAt time.Time
	scopes    []string

	authTime time.Time
	amr      []string
}

type refreshTokenRequest struct {
	*refreshToken
}

func (r *refreshTokenRequest) GetAMR() []string {
	return []string{}
}

func (r *refreshTokenRequest) GetAudience() []string {
	return r.audience
}

func (r *refreshTokenRequest) GetAuthTime() time.Time {
	return r.authTime
}

func (r *refreshTokenRequest) GetClientID() string {
	return r.clientID
}

func (r *refreshTokenRequest) GetScopes() []string {
	return r.scopes
}

func (r *refreshTokenRequest) GetSubject() string {
	return r.subject
}

func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) {
	r.scopes = scopes
}
