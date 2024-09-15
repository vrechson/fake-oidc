package oidc

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

func newClient(config config) clientWithRedirectGlobs {
	c := &client{config: config, id: "dev-client", secret: "secure-secret"}
	return clientWithRedirectGlobs{c}
}

func (c *client) GetID() string {
	return c.id
}

func (c *client) RedirectURIs() []string {
	// implementing HasRedirectGlobs instead
	return []string{}
}

func (c *client) PostLogoutRedirectURIs() []string {
	// implementing HasRedirectGlobs instead
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
	return true
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

// HasRedirectGlobs

type clientWithRedirectGlobs struct {
	*client
}

var _ op.HasRedirectGlobs = (*client)(nil)

func (c *client) RedirectURIGlobs() []string {
	// op uses bmatcuk/doublestar package to match globs
	return []string{"**"}
}

func (c *client) PostLogoutRedirectURIGlobs() []string {
	// op uses bmatcuk/doublestar package to match globs
	return []string{"**"}
}
