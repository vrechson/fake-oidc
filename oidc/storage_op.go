package oidc

import (
	"context"
	"errors"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

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

	// Set basic claims
	userinfo.Subject = user.id
	userinfo.Name = user.name
	userinfo.Email = user.email
	userinfo.EmailVerified = oidc.Bool(user.emailVerified)
	userinfo.PhoneNumber = user.phoneNumber
	userinfo.PhoneNumberVerified = user.phoneNumberVerified

	// Set profile claims if profile scope is requested
	if contains(scopes, "profile") {
		userinfo.PreferredUsername = user.profile.PreferredUsername
		userinfo.Profile = user.profile.ProfileURL
		userinfo.Picture = user.profile.Picture
		userinfo.Website = user.profile.Website
		userinfo.Gender = oidc.Gender(user.profile.Gender)
		userinfo.Birthdate = user.profile.Birthdate
		userinfo.Zoneinfo = user.profile.Zoneinfo
		if user.profile.Locale != "" {
			userinfo.Locale = oidc.NewLocale(language.MustParse(user.profile.Locale))
		}
		userinfo.GivenName = user.profile.FirstName
		userinfo.FamilyName = user.profile.LastName
		userinfo.MiddleName = user.profile.MiddleName
		userinfo.Nickname = user.profile.Nickname
	}

	// Set address claims if address scope is requested
	if contains(scopes, "address") {
		userinfo.Address = &oidc.UserInfoAddress{
			Formatted:     user.address.Formatted,
			StreetAddress: user.address.StreetAddress,
			Locality:      user.address.Locality,
			Region:        user.address.Region,
			PostalCode:    user.address.PostalCode,
			Country:       user.address.Country,
		}
	}

	// Add custom claims
	if userinfo.Claims == nil {
		userinfo.Claims = make(map[string]any)
	}
	for key, value := range user.customClaims {
		userinfo.Claims[key] = value
	}

	return nil
}

func (s *inmemStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return errors.New("token not found")
	}

	user, ok := s.users[token.subject]
	if !ok {
		return errors.New("user not found")
	}

	// Set basic claims
	userinfo.Subject = user.id
	userinfo.Name = user.name
	userinfo.Email = user.email
	userinfo.EmailVerified = oidc.Bool(user.emailVerified)
	userinfo.PhoneNumber = user.phoneNumber
	userinfo.PhoneNumberVerified = user.phoneNumberVerified

	// Set profile claims
	userinfo.PreferredUsername = user.profile.PreferredUsername
	userinfo.Profile = user.profile.ProfileURL
	userinfo.Picture = user.profile.Picture
	userinfo.Website = user.profile.Website
	userinfo.Gender = oidc.Gender(user.profile.Gender)
	userinfo.Birthdate = user.profile.Birthdate
	userinfo.Zoneinfo = user.profile.Zoneinfo
	if user.profile.Locale != "" {
		userinfo.Locale = oidc.NewLocale(language.MustParse(user.profile.Locale))
	}
	userinfo.GivenName = user.profile.FirstName
	userinfo.FamilyName = user.profile.LastName
	userinfo.MiddleName = user.profile.MiddleName
	userinfo.Nickname = user.profile.Nickname

	// Set address claims
	userinfo.Address = &oidc.UserInfoAddress{
		Formatted:     user.address.Formatted,
		StreetAddress: user.address.StreetAddress,
		Locality:      user.address.Locality,
		Region:        user.address.Region,
		PostalCode:    user.address.PostalCode,
		Country:       user.address.Country,
	}

	// Add custom claims
	if userinfo.Claims == nil {
		userinfo.Claims = make(map[string]any)
	}
	for key, value := range user.customClaims {
		userinfo.Claims[key] = value
	}

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
