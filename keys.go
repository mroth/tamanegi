package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/pem"
)

const OnionSize = 10 // Onion name size in bytes (equal to `sha1.Size / 2`)

// E_MIN is minimum public key exponent.
const E_MIN = 65537 + 2 //scallion: 0xFFFFFF + 2

// E_MAX is maximum public key exponent.  Go wants this to fit in 32-bit to
// ensure similar behavior across platforms, for documentation see source of
// rsa.PublicKey.Validate() where that fact is hidden.
const E_MAX = 1<<31 - 1 //scallion: 0xFFFFFFFF

// NewKey generates a RSA keypair of 1024 bits
func NewKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

// OnionNameBytes is a base32 encoding of the .onion hash, as a byte slice.
func OnionNameBytes(pk *rsa.PrivateKey) []byte {
	hash := computeOnionHash(pk)
	onionName := make([]byte, base32.StdEncoding.EncodedLen(OnionSize))
	base32.StdEncoding.Encode(onionName, hash)
	return onionName
}

// OnionNameString is a base32 encoding of the .onion hash, as a string.
func OnionNameString(pk *rsa.PrivateKey) string {
	hash := computeOnionHash(pk)
	return base32.StdEncoding.EncodeToString(hash)
}

// Compute the .onion hash for a given RSA key.
//
// This is the first half of the sha1Sum for the public key.
func computeOnionHash(pk *rsa.PrivateKey) []byte {
	pubASN1, err := asn1.Marshal(pk.PublicKey)
	if err != nil {
		// TODO: check Err
	}

	sha := sha1.Sum(pubASN1)
	return sha[:OnionSize]
}

func encPrivKey(pk *rsa.PrivateKey) []byte {
	privASN1 := x509.MarshalPKCS1PrivateKey(pk)
	return pem.EncodeToMemory(
		&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   privASN1,
		},
	)
}
