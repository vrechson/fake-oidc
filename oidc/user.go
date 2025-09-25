package oidc

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

type user struct {
	id                  string
	username            string
	name                string
	email               string
	emailVerified       bool
	profile             ProfileInfo
	address             AddressInfo
	phoneNumber         string
	phoneNumberVerified bool
	customClaims        map[string]interface{}
}

// createUserFromConfig creates a user from the configuration
func createUserFromConfig(username string, userConfig UserProfile) *user {
	// Generate a consistent ID based on username
	h := sha1.New()
	h.Write([]byte(username))
	userID := hex.EncodeToString(h.Sum(nil))

	// Use configured name or generate from username
	name := userConfig.Name
	if name == "" {
		name = strings.ToUpper(username[:1]) + username[1:]
	}

	// Use configured email or generate from username
	email := userConfig.Email
	if email == "" {
		email = username + "@idm.local"
	}

	return &user{
		id:                  userID,
		username:            username,
		name:                name,
		email:               email,
		emailVerified:       userConfig.EmailVerified,
		profile:             userConfig.Profile,
		address:             userConfig.Address,
		phoneNumber:         userConfig.PhoneNumber,
		phoneNumberVerified: userConfig.PhoneNumberVerified,
		customClaims:        userConfig.CustomClaims,
	}
}
