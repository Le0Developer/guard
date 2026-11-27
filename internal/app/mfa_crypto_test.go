package app

import (
	"encoding/base32"
	"encoding/base64"
	"testing"
)

func TestMFATOTPVector(t *testing.T) {
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if got := mfaTOTP(s, 1); got != "287082" {
		t.Fatalf("got %s", got)
	}
}
func TestMFASecretBinding(t *testing.T) {
	a := &App{Config: Config{MFAEncryptionKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}
	c, e := a.mfaSeal(1, "secret")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.mfaOpen(2, c); e == nil {
		t.Fatal("accepted different user")
	}
	if v, e := a.mfaOpen(1, c); e != nil || v != "secret" {
		t.Fatal(v, e)
	}
}
func TestMFAWebOrigin(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://", "file:///tmp/key"} {
		a := &App{Config: Config{Domain: origin}}
		if _, e := a.mfaWeb(); e == nil {
			t.Fatalf("accepted %s", origin)
		}
	}
	for _, origin := range []string{"https://guard.example", "http://localhost:4444"} {
		a := &App{Config: Config{Domain: origin}}
		if _, e := a.mfaWeb(); e != nil {
			t.Fatal(origin, e)
		}
	}
}
func TestMFARecoveryNormalization(t *testing.T) {
	if mfaRecoveryHash(1, "ABCD-EF01 2345") != mfaRecoveryHash(1, "abcdef012345") {
		t.Fatal("normalization differs")
	}
	if mfaRecoveryHash(1, "code") == mfaRecoveryHash(2, "code") {
		t.Fatal("recovery hash not user bound")
	}
}
