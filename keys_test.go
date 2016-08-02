package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// Verify given a RSA key, we generation onion hashes in a way that is
// consistent with other services.
//
// To test, load a private key generated from eschalot and verify we end up
// with the same .onion name.
func TestOnionName(t *testing.T) {
	sampleDER := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQDi+NrBJia8CjsxJP21cspJiZTF4kEsVrQwmPSMwEm/EMK61yJE
sus/msV4vb3uxRlUr34eQXEe296+339GginIGu0L6T3QYaur2NumtD6r2A9oL8GG
Dl2Tg6LHqBhtnjb+8ggVVLu7qPGc2T7z00XMADGK//XQEIUiMd0byIsqdQIDBYlD
An86IkNtV+OfLPUwsP9axo0TNsBWw63VnKRQjwy0h2QcrPEo+kcyi7z5cpKFqmCb
D4TC/w/pjNuaVmzM53sxRgm9EX1ztIGb7ur+rJuk7B0Mm2biVsu/Qn8I8U45WdQv
F1ntngn8c1764tKk0XWJVEjRvO+JeQZweHtMqwY79t9LAkEA+B/Lb9mzzZVmbEzt
Gql6S/3/wkBpA5owNEkO+3EYDl3LEg+s9BXfGoWWM4HlWhVmW5q1rcGQ3JDY2lXO
TwueqQJBAOotLqWHnwVyeMpOxHTZL92KmfirydcxtrTmrAmVt3SkZWSVOdrjRT9S
azJqQrsmb4XIrWM4QShxzuKpq5e0CO0CQQDFskPcA7CXqXR1a/iwj3lSUCI9LzT0
gvIGf+9acDS8mL9ovl9I/iOkGU9oNarKdd+KQdpST6L60fqEWx//TpfjAkBCxWEl
hxNQc6e7jEuhNf8nLx/YfvJYm+fAEDsuZBzs0spgMjYuUFPecqLAouKIDphXQ4/T
9XrDZmMhKnQXJZa3AkBOqTda1qYYRLCY2HkdxKdqjpVAkdIJ4+/sOEpaELo6PBs1
LwKKbKkPq5qFRXdi8xicP36tP8E2n4RF7jnNSYMh
-----END RSA PRIVATE KEY-----`)
	expected := "TESTHZX3NYATVZQF"

	block, _ := pem.Decode(sampleDER)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error("Failed to parse decoded PEM block")
	}

	onionName := OnionNameString(key)
	if onionName != expected {
		t.Error("Expected ", expected, ", got ", onionName)
	}
}

/*
	------------ BENCHMARKS! ------------
*/

func BenchmarkNewKey(b *testing.B) {
	for n := 0; n < b.N; n++ {
		NewKey()
	}
}

func BenchmarkComputeOnionHash(b *testing.B) {
	key, _ := NewKey()
	for n := 0; n < b.N; n++ {
		computeOnionHash(key)
	}
}

func BenchmarkOnionNameBytes(b *testing.B) {
	key, _ := NewKey()
	for n := 0; n < b.N; n++ {
		OnionNameBytes(key)
	}
}

func BenchmarkOnionNameString(b *testing.B) {
	key, _ := NewKey()
	for n := 0; n < b.N; n++ {
		OnionNameString(key)
	}
}
