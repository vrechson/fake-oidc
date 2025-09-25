package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the complete configuration for the fake OIDC server
type Config struct {
	Server   ServerConfig   `json:"server"`
	Client   ClientConfig   `json:"client"`
	UserData UserDataConfig `json:"user_data"`
	Issuer   IssuerConfig   `json:"issuer"`
	Features FeaturesConfig `json:"features"`
}

// ServerConfig contains server-specific configuration
type ServerConfig struct {
	Host string    `json:"host"`
	Port string    `json:"port"`
	TLS  TLSConfig `json:"tls"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// ClientConfig contains OIDC client configuration
type ClientConfig struct {
	ID                     string   `json:"id"`
	Secret                 string   `json:"secret"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
}

// UserDataConfig contains user data configuration
type UserDataConfig struct {
	DefaultUser UserProfile `json:"default_user"`
}

// UserProfile represents a user's profile with nested fields
type UserProfile struct {
	ID                  string                 `json:"id"`
	Username            string                 `json:"username"`
	Name                string                 `json:"name"`
	Email               string                 `json:"email"`
	EmailVerified       bool                   `json:"email_verified"`
	Profile             ProfileInfo            `json:"profile"`
	Address             AddressInfo            `json:"address"`
	PhoneNumber         string                 `json:"phone_number"`
	PhoneNumberVerified bool                   `json:"phone_number_verified"`
	CustomClaims        map[string]interface{} `json:"custom_claims"`
}

// ProfileInfo contains detailed profile information
type ProfileInfo struct {
	FirstName         string `json:"first_name"`
	LastName          string `json:"last_name"`
	MiddleName        string `json:"middle_name"`
	Nickname          string `json:"nickname"`
	PreferredUsername string `json:"preferred_username"`
	ProfileURL        string `json:"profile_url"`
	Picture           string `json:"picture"`
	Website           string `json:"website"`
	Gender            string `json:"gender"`
	Birthdate         string `json:"birthdate"`
	Zoneinfo          string `json:"zoneinfo"`
	Locale            string `json:"locale"`
}

// AddressInfo contains address information
type AddressInfo struct {
	Formatted     string `json:"formatted"`
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

// IssuerConfig contains issuer configuration
type IssuerConfig struct {
	URL string `json:"url"`
}

// FeaturesConfig contains feature flags and supported capabilities
type FeaturesConfig struct {
	AllowInsecure   bool     `json:"allow_insecure"`
	EnableLogging   bool     `json:"enable_logging"`
	RequirePKCE     bool     `json:"require_pkce"`
	SupportedScopes []string `json:"supported_scopes"`
	SupportedClaims []string `json:"supported_claims"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(configPath string) (*Config, error) {
	// If no config path provided, try default locations
	if configPath == "" {
		possiblePaths := []string{
			"config.json",
			"config.yaml",
			"config.yml",
			"./config.json",
			"./config.yaml",
			"./config.yml",
		}

		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}

		if configPath == "" {
			// Return default config if no file found
			return getDefaultConfig(), nil
		}
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse based on file extension
	ext := filepath.Ext(configPath)
	var config Config

	switch ext {
	case ".json":
		err = json.Unmarshal(data, &config)
	case ".yaml", ".yml":
		// For now, we'll only support JSON. YAML support can be added later if needed
		return nil, fmt.Errorf("YAML config files not yet supported, please use JSON")
	default:
		// Try JSON as default
		err = json.Unmarshal(data, &config)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate and set defaults
	config.setDefaults()

	return &config, nil
}

// getDefaultConfig returns a default configuration
func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "",
			Port: "7835",
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "",
				KeyFile:  "",
			},
		},
		Client: ClientConfig{
			ID:                     "dev-client",
			Secret:                 "secure-secret",
			RedirectURIs:           []string{"**"},
			PostLogoutRedirectURIs: []string{"**"},
		},
		UserData: UserDataConfig{
			DefaultUser: UserProfile{
				ID:            "user123",
				Username:      "testuser",
				Name:          "Test User",
				Email:         "testuser@example.com",
				EmailVerified: true,
				Profile: ProfileInfo{
					FirstName:         "Test",
					LastName:          "User",
					Nickname:          "testy",
					PreferredUsername: "testuser",
					ProfileURL:        "https://example.com/profile/testuser",
					Picture:           "https://example.com/avatar/testuser.jpg",
					Website:           "https://example.com",
					Gender:            "other",
					Birthdate:         "1990-01-01",
					Zoneinfo:          "America/New_York",
					Locale:            "en-US",
				},
				Address: AddressInfo{
					Formatted:     "123 Main St, Anytown, ST 12345, USA",
					StreetAddress: "123 Main St",
					Locality:      "Anytown",
					Region:        "ST",
					PostalCode:    "12345",
					Country:       "USA",
				},
				PhoneNumber:         "+1-555-123-4567",
				PhoneNumberVerified: true,
				CustomClaims: map[string]interface{}{
					"department":  "Engineering",
					"role":        "Developer",
					"permissions": []string{"read", "write", "admin"},
					"metadata": map[string]interface{}{
						"employee_id": "EMP001",
						"hire_date":   "2020-01-15",
						"manager":     "john.doe@example.com",
					},
				},
			},
		},
		Issuer: IssuerConfig{
			URL: "",
		},
		Features: FeaturesConfig{
			AllowInsecure:   true,
			EnableLogging:   false,
			RequirePKCE:     false,
			SupportedScopes: []string{"openid", "profile", "email", "phone", "address", "offline_access"},
			SupportedClaims: []string{"sub", "name", "email", "email_verified", "phone_number", "phone_number_verified", "profile", "address"},
		},
	}
}

// setDefaults sets default values for any missing configuration
func (c *Config) setDefaults() {
	if c.Server.Port == "" {
		c.Server.Port = "7835"
	}

	if c.Client.ID == "" {
		c.Client.ID = "dev-client"
	}

	if c.Client.Secret == "" {
		c.Client.Secret = "secure-secret"
	}

	if len(c.Client.RedirectURIs) == 0 {
		c.Client.RedirectURIs = []string{"**"}
	}

	if len(c.Client.PostLogoutRedirectURIs) == 0 {
		c.Client.PostLogoutRedirectURIs = []string{"**"}
	}

	if c.Issuer.URL == "" {
		c.Issuer.URL = "http://localhost:" + c.Server.Port
	}

	if len(c.Features.SupportedScopes) == 0 {
		c.Features.SupportedScopes = []string{"openid", "profile", "email", "phone", "address", "offline_access"}
	}

	if len(c.Features.SupportedClaims) == 0 {
		c.Features.SupportedClaims = []string{"sub", "name", "email", "email_verified", "phone_number", "phone_number_verified", "profile", "address"}
	}
}

// GetServerAddress returns the full server address
func (c *Config) GetServerAddress() string {
	if c.Server.Host == "" {
		return ":" + c.Server.Port
	}
	return c.Server.Host + ":" + c.Server.Port
}

// GetIssuerURL returns the issuer URL, constructing it if needed
func (c *Config) GetIssuerURL() string {
	if c.Issuer.URL != "" {
		return c.Issuer.URL
	}

	protocol := "http"
	if c.Server.TLS.Enabled {
		protocol = "https"
	}

	host := c.Server.Host
	if host == "" {
		host = "localhost"
	}

	return fmt.Sprintf("%s://%s:%s", protocol, host, c.Server.Port)
}
