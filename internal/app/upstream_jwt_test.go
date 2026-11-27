package app

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/le0developer/guard/internal/db"
)

func TestUpstreamJWTBoundaries(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":"one","crv":"P-256","alg":"ES256","x":%q,"y":%q}]}`, enc(key.X.FillBytes(make([]byte, 32))), enc(key.Y.FillBytes(make([]byte, 32))))
	}))
	defer srv.Close()
	p := db.UpstreamProvider{Issuer: "https://issuer.example", ClientID: "guard", SigningAlg: "RS256 ES256", JwksUrl: srv.URL}
	a := &App{}
	sign := func(header string, c map[string]any) string {
		b, _ := json.Marshal(c)
		input := enc([]byte(header)) + "." + enc(b)
		digest := sha256.Sum256([]byte(input))
		r, s, e := ecdsa.Sign(rand.Reader, key, digest[:])
		if e != nil {
			t.Fatal(e)
		}
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return input + "." + enc(sig)
	}
	claims := func() map[string]any {
		return map[string]any{"iss": p.Issuer, "sub": "person", "aud": p.ClientID, "iat": time.Now().Unix(), "exp": time.Now().Unix() + 300, "nonce": "nonce"}
	}
	header := `{"alg":"ES256","kid":"one"}`
	if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(header, claims()), upstreamIDToken, "nonce"); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(map[string]any){"issuer": func(c map[string]any) { c["iss"] = "other" }, "audience": func(c map[string]any) { c["aud"] = "other" }, "nonce": func(c map[string]any) { c["nonce"] = "other" }, "expired": func(c map[string]any) { c["exp"] = time.Now().Unix() - 1 }, "future": func(c map[string]any) { c["iat"] = time.Now().Unix() + 100 }, "multi audience": func(c map[string]any) { c["aud"] = []string{"guard", "other"} }, "null sid": func(c map[string]any) { c["sid"] = nil }}
	for _, field := range []string{"sub", "sid", "jti"} {
		cases["empty "+field] = func(c map[string]any) { c[field] = "" }
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			c := claims()
			modify(c)
			if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(header, c), upstreamIDToken, "nonce"); !errors.Is(e, errUpstreamJWTInvalid) {
				t.Fatalf("got %v", e)
			}
		})
	}
	for _, h := range []string{`{"alg":"none"}`, `{"alg":"HS256"}`, `{"alg":"ES256","alg":"ES256"}`, `{"alg":"ES256","jku":"https://evil.example"}`, `{"alg":"RS256"}`, `{"alg":"ES256","typ":"logout+jwt"}`} {
		if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(h, claims()), upstreamIDToken, "nonce"); !errors.Is(e, errUpstreamJWTInvalid) {
			t.Fatalf("header %s: %v", h, e)
		}
	}
	logout := claims()
	delete(logout, "nonce")
	logout["jti"] = "event"
	logout["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}
	if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(`{"alg":"ES256","typ":"logout+jwt"}`, logout), upstreamLogoutToken, ""); e != nil {
		t.Fatal(e)
	}
	logout["sid"] = ""
	if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(header, logout), upstreamLogoutToken, ""); !errors.Is(e, errUpstreamJWTInvalid) {
		t.Fatalf("empty logout sid: %v", e)
	}
	delete(logout, "sid")
	logout["nonce"] = nil
	if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(header, logout), upstreamLogoutToken, ""); !errors.Is(e, errUpstreamJWTInvalid) {
		t.Fatal(e)
	}
	if requests.Load() != 1 {
		t.Fatalf("cache requests %d", requests.Load())
	}
	p.Revision++
	if _, e := a.verifyUpstreamJWT(context.Background(), p, sign(header, claims()), upstreamIDToken, "nonce"); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 2 {
		t.Fatal("revision failed to invalidate")
	}
}
func TestUpstreamStrictJSON(t *testing.T) {
	for _, s := range []string{`{"a":{"b":1,"b":2}}`, `{"a":1} {}`, `{"a":1,"a":2}`} {
		var v any
		if strictJSON([]byte(s), &v) == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestUpstreamJWKSUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	a := &App{}
	_, e := a.upstreamSigningKeys(context.Background(), db.UpstreamProvider{JwksUrl: srv.URL}, "")
	if !errors.Is(e, errUpstreamJWKSUnavailable) {
		t.Fatal(e)
	}
}

func TestUpstreamJWKSRotationThrottle(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	var requests atomic.Int32
	var rotated atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		kid := "old"
		if rotated.Load() {
			kid = "new"
		}
		fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, kid, enc(key.X.FillBytes(make([]byte, 32))), enc(key.Y.FillBytes(make([]byte, 32))))
	}))
	defer srv.Close()
	a := &App{}
	p := db.UpstreamProvider{JwksUrl: srv.URL, SigningAlg: "ES256"}
	if _, e := a.upstreamSigningKeys(context.Background(), p, "old"); e != nil {
		t.Fatal(e)
	}
	rotated.Store(true)
	for range 3 {
		if _, e := a.upstreamSigningKeys(context.Background(), p, "new"); !errors.Is(e, errUpstreamJWKSUnavailable) {
			t.Fatal(e)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("unknown kid was not throttled")
	}
	a.upstreamKeys.mu.Lock()
	for k, v := range a.upstreamKeys.entries {
		v.attempted = time.Now().Add(-11 * time.Second)
		a.upstreamKeys.entries[k] = v
	}
	a.upstreamKeys.mu.Unlock()
	keys, e := a.upstreamSigningKeys(context.Background(), p, "new")
	if e != nil || len(keys) != 1 || keys[0].kid != "new" {
		t.Fatalf("rotation: %v %v", keys, e)
	}
	if requests.Load() != 2 {
		t.Fatal("rotation did not fetch")
	}
}

func TestUpstreamSignatureAlgorithms(t *testing.T) {
	rsaKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			msg := []byte("signed input")
			var hash crypto.Hash
			var digest []byte
			switch alg[len(alg)-3:] {
			case "256":
				hash = crypto.SHA256
				v := sha256.Sum256(msg)
				digest = v[:]
			case "384":
				hash = crypto.SHA384
				v := sha512.Sum384(msg)
				digest = v[:]
			case "512":
				hash = crypto.SHA512
				v := sha512.Sum512(msg)
				digest = v[:]
			}
			var pub crypto.PublicKey
			var sig []byte
			switch alg[:2] {
			case "RS":
				pub = &rsaKey.PublicKey
				sig, e = rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
			case "PS":
				pub = &rsaKey.PublicKey
				sig, e = rsa.SignPSS(rand.Reader, rsaKey, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			case "ES":
				curve := elliptic.P256()
				if alg == "ES384" {
					curve = elliptic.P384()
				}
				if alg == "ES512" {
					curve = elliptic.P521()
				}
				key, err := ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				pub = &key.PublicKey
				r, s, err := ecdsa.Sign(rand.Reader, key, digest)
				if err != nil {
					t.Fatal(err)
				}
				n := (curve.Params().BitSize + 7) / 8
				sig = append(r.FillBytes(make([]byte, n)), s.FillBytes(make([]byte, n))...)
			case "Ed":
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				pub = public
				sig = ed25519.Sign(private, msg)
			}
			if e != nil {
				t.Fatal(e)
			}
			if !verifyUpstreamSignature(alg, pub, msg, sig) {
				t.Fatal("valid signature rejected")
			}
			sig[0] ^= 1
			if verifyUpstreamSignature(alg, pub, msg, sig) {
				t.Fatal("bad signature accepted")
			}
		})
	}
}

func TestUpstreamJWKSProviderIsolation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	body := fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"key","crv":"P-256","x":%q,"y":%q}]}`, enc(key.X.FillBytes(make([]byte, 32))), enc(key.Y.FillBytes(make([]byte, 32))))
	started, release := make(chan struct{}), make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; fmt.Fprint(w, body) }))
	defer slow.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer fast.Close()
	a := &App{}
	cached := db.UpstreamProvider{Issuer: "cached", JwksUrl: fast.URL, SigningAlg: "ES256"}
	if _, e := a.upstreamSigningKeys(context.Background(), cached, "key"); e != nil {
		t.Fatal(e)
	}
	slowProvider := db.UpstreamProvider{Issuer: "slow", JwksUrl: slow.URL, SigningAlg: "ES256"}
	go a.upstreamSigningKeys(context.Background(), slowProvider, "key")
	<-started
	for _, p := range []db.UpstreamProvider{cached, {Issuer: "uncached", JwksUrl: fast.URL, SigningAlg: "ES256"}} {
		done := make(chan error, 1)
		go func() { _, e := a.upstreamSigningKeys(context.Background(), p, "key"); done <- e }()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(500 * time.Millisecond):
			t.Error("unrelated provider blocked by slow JWKS")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, e := a.upstreamSigningKeys(ctx, slowProvider, "key"); done <- e }()
	select {
	case e := <-done:
		if !errors.Is(e, errUpstreamJWKSUnavailable) {
			t.Errorf("canceled waiter: %v", e)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("same provider wait ignored cancellation")
	}
	shared := make(chan error, 1)
	go func() { _, e := a.upstreamSigningKeys(context.Background(), slowProvider, "key"); shared <- e }()
	releaseOnce.Do(func() { close(release) })
	select {
	case e := <-shared:
		if e != nil {
			t.Errorf("shared fetch: %v", e)
		}
	case <-time.After(time.Second):
		t.Error("shared fetch did not complete")
	}
}

func TestUpstreamJWKSCachesForADay(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	body := fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"daily","crv":"P-256","x":%q,"y":%q}]}`, enc(key.X.FillBytes(make([]byte, 32))), enc(key.Y.FillBytes(make([]byte, 32))))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, body) }))
	defer server.Close()
	a := &App{}
	p := db.UpstreamProvider{Issuer: "daily-provider", JwksUrl: server.URL, SigningAlg: "ES256"}
	if _, err = a.upstreamSigningKeys(context.Background(), p, "daily"); err != nil {
		t.Fatal(err)
	}
	age := func(d time.Duration) {
		a.upstreamKeys.mu.Lock()
		defer a.upstreamKeys.mu.Unlock()
		for id, entry := range a.upstreamKeys.entries {
			entry.fetched = time.Now().Add(-d)
			entry.attempted = entry.fetched
			a.upstreamKeys.entries[id] = entry
		}
	}
	age(23 * time.Hour)
	if _, err = a.upstreamSigningKeys(context.Background(), p, "daily"); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Errorf("JWKS refetched within24hours: %d", requests.Load())
	}
	age(25 * time.Hour)
	if _, err = a.upstreamSigningKeys(context.Background(), p, "daily"); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Errorf("expired JWKS did not refresh: %d", requests.Load())
	}
}
