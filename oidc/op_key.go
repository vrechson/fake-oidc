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
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALviu84rlVlz9hcu
s4zq7gd+CRy+/vYp/ag2pG948MjukaRIGxAvU334vWDi7KNGI8jJbLCyR/7t/szB
xDihofBBeCwSwmSBnNQDmjGdKGDPVbMp+d7SlPAL3V+ZejFnsVCwwfXrbLLIYjBU
fG7thaHRtkPDejQaUxrQG+E8FPfnAgMBAAECgYA9xbbvev7YcTrItm8L9rWZuwNt
8xHKh1XBd22qxL2Nono55AcZ1CWENkK1VwZsTAQ54JeepI7tLvxl/5Lu951Q2vh+
rZt+oLWWEBlwG7nj1rp/V8R6iTP1Iy3oCMke/ZpXiTgLtr5Y46WAkLr7iCPn8Hsg
F3fGYsYhvYoLZ7q7qQJBAOrcNQ8LbcYrXyLMiKlvv3xz4H+G9s4ysAGjnhTWXz/Q
t61+Uxr/R95RbRiim6BaVPI2vKYnHb47WUT6qua94NMCQQDMzBxkFFh/obVAzsxO
1i7zKi1o50n93fydFhAXQvUvKxcHJHL71wIr5LqnJ1JzU2LG6mP/xzC0jXeHWqhV
k4AdAkAEfJh25Rz/wCxdGdMyiXP7CKutRALLBaTfIyUN+Npw+afIpLUput7AnIWd
Bt46Pf+JcQpBklW7IJ8f9jn1loMJAkBIaRLQv/Daj86Kb5QFe+11xL/xi3W58TdU
Q2zFDMOsPcwSlmyhZtA5vNHSMDES3bTbKBzbXw51iF9u2DsUpuZxAkEA4T5KuXAm
NOvlLxdhaUuj0f5GuOoX/Ck82X9dpvFUs3XMhh2nUx+GZ18BzO9DeVBpq30QBBn7
Qw3u1h7u7om8oA==
-----END PRIVATE KEY-----`))
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
