package main

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

func makeAKey() *signingKey {
	key, err := rsa.GenerateKey(rand.Reader, 16)
	if err != nil {
		panic(err)
	}

	return &signingKey{
		id:  uuid.NewString(),
		key: key,
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
