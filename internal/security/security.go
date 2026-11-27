// Package security contains Guard's stdlib cryptographic and URL primitives.
package security

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const passwordIterations = 600000

func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func Equal(a, b string) bool {
	x := sha256.Sum256([]byte(a))
	y := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}
func HashPassword(s string) (string, error) {
	if len(s) < 8 || len(s) > 1024 {
		return "", errors.New("password must contain 8–1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, s, salt, passwordIterations, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2-sha256$" + strconv.Itoa(passwordIterations) + "$" + base64.RawURLEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(key), nil
}
func VerifyPassword(s, hash string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" || len(s) > 1024 {
		return false
	}
	n, err := strconv.Atoi(p[1])
	if err != nil || n < 100000 || n > 1000000 {
		return false
	}
	salt, e1 := base64.RawURLEncoding.DecodeString(p[2])
	want, e2 := base64.RawURLEncoding.DecodeString(p[3])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, s, salt, n, 32)
	return err == nil && hmac.Equal(got, want)
}
func SafeRedirect(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.Contains(s, "\\") || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return s
}
func URL(s string) (*url.URL, error) {
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || strings.ContainsAny(s, "\\,") {
		return nil, errors.New("invalid URL")
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid HTTP URL")
	}
	return u, nil
}
func Origin(s string) (string, error) {
	u, err := URL(s)
	if err != nil {
		return "", err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("origin cannot contain a path, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}
