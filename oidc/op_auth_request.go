package oidc

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type authRequest struct {
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

func (r *authRequest) GetID() string {
	return r.id
}
func (r *authRequest) GetACR() string {
	return ""
}
func (r *authRequest) GetAMR() []string {
	return []string{}
}
func (r *authRequest) GetAudience() []string {
	return []string{r.audience}
}
func (r *authRequest) GetAuthTime() time.Time {
	return r.authTime
}
func (r *authRequest) GetClientID() string {
	return r.clientID
}
func (r *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return r.codeChallenge
}
func (r *authRequest) GetNonce() string {
	return r.nonce
}
func (r *authRequest) GetRedirectURI() string {
	return r.redirectURI
}
func (r *authRequest) GetResponseType() oidc.ResponseType {
	return r.responseType
}
func (r *authRequest) GetResponseMode() oidc.ResponseMode {
	return r.responseMode
}
func (r *authRequest) GetScopes() []string {
	return r.scopes
}
func (r *authRequest) GetState() string {
	return r.state
}
func (r *authRequest) GetSubject() string {
	return r.subject
}
func (r *authRequest) Done() bool {
	return r.done
}
