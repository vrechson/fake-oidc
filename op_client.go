package main

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type client struct {
	config config
	id     string
	secret string
}

func newClient(config config) client {
	return client{config: config, id: "dev-client", secret: "secure-secret"}
}

func (c *client) GetID() string {
	return c.id
}

func (c *client) RedirectURIs() []string {
	return []string{"http://localhost:3000/auth/complete"}
}

func (c *client) PostLogoutRedirectURIs() []string {
	return c.RedirectURIs()
}

func (c *client) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeWeb
}

func (c *client) AuthMethod() oidc.AuthMethod {
	return oidc.AuthMethodBasic
}

func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

func (c *client) LoginURL(authRequestID string) string {
	return c.config.origin + "/login?authRequestID=" + authRequestID
}

func (c *client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}

func (c *client) IDTokenLifetime() time.Duration {
	return time.Second * 900
}

func (c *client) DevMode() bool {
	return false
}

func (c *client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *client) IsScopeAllowed(scope string) bool {
	return true
}

func (c *client) IDTokenUserinfoClaimsAssertion() bool {
	return true
}

func (c *client) ClockSkew() time.Duration {
	return time.Second * 0
}
