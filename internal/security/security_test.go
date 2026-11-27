package security

import (
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) || VerifyPassword("wrong", h) {
		t.Fatal("password verification")
	}
	if VerifyPassword("x", "pbkdf2-sha256$999999999$bad$bad") {
		t.Fatal("accepted corrupt hash")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt reused")
	}
}
func TestSafeRedirect(t *testing.T) {
	for _, v := range []string{"https://evil.example/", "//evil.example/", "/\\evil", "/\nfoo", ""} {
		if SafeRedirect(v) != "/" {
			t.Fatalf("accepted %q", v)
		}
	}
	if SafeRedirect("/oauth2/authorize?x=y") != "/oauth2/authorize?x=y" {
		t.Fatal("lost continuation")
	}
}
func TestToken(t *testing.T) {
	a := Token()
	b := Token()
	if a == b || len(a) < 40 || strings.ContainsAny(a, "+/=") {
		t.Fatal("invalid random token")
	}
	if !Equal(a, a) || Equal(a, b) {
		t.Fatal("comparison")
	}
	if Hash(a) == a {
		t.Fatal("not hashed")
	}
}
func TestOrigin(t *testing.T) {
	for _, s := range []string{"https://example.com/path", "https://x@host", "https://host?x=y", "https://host#x", "https://a,b", "https://host\\evil"} {
		if _, err := Origin(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if v, err := Origin("https://example.com:443/"); err != nil || v != "https://example.com" {
		t.Fatalf("%q %v", v, err)
	}
}
