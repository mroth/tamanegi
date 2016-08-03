package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"testing"
)

func TestMarshalPubKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	native, _ := asn1.Marshal(key.PublicKey)
	local, err := MarshalPubKey(key.PublicKey)

	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(native, local) {
		t.Fatalf("expected: %x, actual: %x", native, local)
	}
}

func TestMarshalPubFast(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	native, _ := asn1.Marshal(key.PublicKey)
	var buf bytes.Buffer
	local, err := MarshalPubKeyFast(&buf, key.PublicKey)

	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(native, local) {
		t.Fatalf("expected: %x, actual: %x", native, local)
	}
}

func BenchmarkNativeAsn1Marshal(b *testing.B) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	for n := 0; n < b.N; n++ {
		asn1.Marshal(key.PublicKey)
	}
}

func BenchmarkAsn1MarshalPubKey(b *testing.B) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	for n := 0; n < b.N; n++ {
		MarshalPubKey(key.PublicKey)
	}
}

func BenchmarkAsn1MarshalPubKeyFast(b *testing.B) {
	var buf bytes.Buffer
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	for n := 0; n < b.N; n++ {
		MarshalPubKeyFast(&buf, key.PublicKey)
	}
}
