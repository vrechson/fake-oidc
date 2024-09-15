package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

func makeAKey() *signingKey {
	block, _ := pem.Decode([]byte(`-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA5hEC8EcyiVjtZTnm
8B0NNN1id/dufWGp7DgECXjV+qIKW/4g203b9/W4+UXsQpjp6S9VyBwnDHwbWO3n
lEHEFwIDAQABAkEApDId68iUe8vY2fbiKBpD06fw3/fahmeOc4Vi9DOmW9GxY1BF
ikO2lb5HP3NF/Pl/tQsB7gekrZPanVNZu4oa2QIhAP0/QPr+EqWnhtV5fKFSLoQI
QgVNdB1iqSocBsFK/vojAiEA6JE/6PMUP7yTAbO2rQNHevxnfP4oq+fPn98m5WbH
a30CIQDmUCp2ma63vP3hE1WHGUh4h1ITpHcfamTSiR6Tl/L/5QIgVB7dqAvsghVa
cx4m8DOkckbDxAFGgs+JWQFlV0qyzR0CIQD3y2lygCE+iK6CzMo+NRYiH1WPpu+f
fHpXfZkA5PnIiw==
-----END PRIVATE KEY-----
`))
	if block == nil {
		panic("pem decode: block is nil")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return &signingKey{
		id:  uuid.NewString(),
		key: key.(*rsa.PrivateKey),
	}
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (s *signingKey) Key() any {
	return s.key
}

func (s *signingKey) ID() string {
	return s.id
}

type publicKey struct {
	internal signingKey
}

func (s *publicKey) Algorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (s *publicKey) Key() any {
	return &s.internal.key.PublicKey
}

func (s *publicKey) ID() string {
	return s.internal.id
}

func (s *publicKey) Use() string {
	return "sig"
}
