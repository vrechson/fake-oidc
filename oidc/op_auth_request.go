package oidc

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthRequest struct {
	id            string
	audience      string
	authTime      time.Time
	clientID      string
	codeChallenge *oidc.CodeChallenge
	nonce         string
	redirectURI   string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	scopes        []string
	state         string
	subject       string
	done          bool
}

func (r *AuthRequest) GetID() string {
	return r.id
}
func (r *AuthRequest) GetACR() string {
	return ""
}
func (r *AuthRequest) GetAMR() []string {
	return []string{}
}
func (r *AuthRequest) GetAudience() []string {
	return []string{r.audience}
}
func (r *AuthRequest) GetAuthTime() time.Time {
	return r.authTime
}
func (r *AuthRequest) GetClientID() string {
	return r.clientID
}
func (r *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return r.codeChallenge
}
func (r *AuthRequest) GetNonce() string {
	return r.nonce
}
func (r *AuthRequest) GetRedirectURI() string {
	return r.redirectURI
}
func (r *AuthRequest) GetResponseType() oidc.ResponseType {
	return r.responseType
}
func (r *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return r.responseMode
}
func (r *AuthRequest) GetScopes() []string {
	return r.scopes
}
func (r *AuthRequest) GetState() string {
	return r.state
}
func (r *AuthRequest) GetSubject() string {
	return r.subject
}
func (r *AuthRequest) Done() bool {
	return r.done
}
