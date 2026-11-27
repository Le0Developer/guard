package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/le0developer/guard/internal/db"
)

var errUpstreamJWTInvalid = errors.New("invalid upstream JWT")
var errUpstreamJWKSUnavailable = errors.New("upstream keys unavailable")

const upstreamJWKSTTL = 24 * time.Hour

type upstreamJWTPurpose uint8

const (
	upstreamIDToken upstreamJWTPurpose = iota
	upstreamLogoutToken
)

type upstreamClaims struct {
	Issuer, Subject, SessionID, JWTID string
	IssuedAt, ExpiresAt, AuthTime     int64
}
type upstreamKey struct {
	kid, alg string
	key      crypto.PublicKey
}
type upstreamKeyEntry struct {
	keys               []upstreamKey
	fetched, attempted time.Time
	inflight           chan struct{}
}
type upstreamKeyCache struct {
	mu      sync.Mutex
	entries map[string]upstreamKeyEntry
}

const automaticUpstreamAlgorithms = "RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 EdDSA"

// The legacy signing_alg column stores the automatic allowlist. Existing single
// algorithm values remain valid until discovery metadata is refreshed.
func allowedUpstreamAlg(config, alg string) bool {
	if !supportedUpstreamAlg(alg) {
		return false
	}
	for _, allowed := range strings.Fields(config) {
		if allowed == alg {
			return true
		}
	}
	return false
}

func supportedUpstreamAlg(s string) bool {
	switch s {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	}
	return false
}

// strictJSON rejects duplicate members, including within nested extension claims.
func strictJSON(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func() error
	value = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return errors.New("duplicate member")
					}
					seen[s] = true
					if e = value(); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = value(); e != nil {
						return e
					}
				}
			default:
				return errors.New("invalid delimiter")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := value(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return json.Unmarshal(raw, dst)
}
func (a *App) verifyUpstreamJWT(ctx context.Context, p db.UpstreamProvider, raw string, purpose upstreamJWTPurpose, nonce string) (upstreamClaims, error) {
	var out upstreamClaims
	invalid := func() (upstreamClaims, error) { return out, errUpstreamJWTInvalid }
	if len(raw) > 65536 {
		return invalid()
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return invalid()
	}
	var h map[string]json.RawMessage
	hb, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || strictJSON(hb, &h) != nil || h == nil {
		return invalid()
	}
	var alg, kid, typ string
	if json.Unmarshal(h["alg"], &alg) != nil || !allowedUpstreamAlg(p.SigningAlg, alg) {
		return invalid()
	}
	if v, ok := h["kid"]; ok {
		if json.Unmarshal(v, &kid) != nil || kid == "" || len(kid) > 512 {
			return invalid()
		}
	}
	for _, k := range []string{"jku", "x5u", "jwk", "x5c", "crit", "b64"} {
		if _, ok := h[k]; ok {
			return invalid()
		}
	}
	if v, ok := h["typ"]; ok {
		if json.Unmarshal(v, &typ) != nil {
			return invalid()
		}
		if purpose == upstreamLogoutToken && typ != "logout+jwt" && typ != "JWT" {
			return invalid()
		}
		if purpose == upstreamIDToken && typ != "JWT" && typ != "application/jwt" {
			return invalid()
		}
	}
	cb, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return invalid()
	}
	var c map[string]json.RawMessage
	if strictJSON(cb, &c) != nil || c == nil {
		return invalid()
	}
	str := func(k string) (string, bool) {
		v, ok := c[k]
		if !ok {
			return "", false
		}
		var s string
		e := json.Unmarshal(v, &s)
		return s, e == nil && string(v) != "null"
	}
	out.Issuer, _ = str("iss")
	out.Subject, _ = str("sub")
	out.SessionID, _ = str("sid")
	out.JWTID, _ = str("jti")
	if out.Issuer != p.Issuer || p.Issuer == "" || p.ClientID == "" || len(out.Subject) > 255 || len(out.SessionID) > 512 {
		return invalid()
	}
	for _, k := range []string{"sub", "sid", "jti"} {
		if _, exists := c[k]; exists {
			if value, ok := str(k); !ok || value == "" {
				return invalid()
			}
		}
	}
	var aud []string
	var single string
	if json.Unmarshal(c["aud"], &single) == nil && single != "" {
		aud = []string{single}
	} else if json.Unmarshal(c["aud"], &aud) != nil {
		return invalid()
	}
	found := false
	for _, s := range aud {
		if s == p.ClientID {
			found = true
		}
	}
	if !found {
		return invalid()
	}
	azp, hasAZP := str("azp")
	if _, exists := c["azp"]; exists && !hasAZP {
		return invalid()
	}
	if hasAZP && azp != p.ClientID || len(aud) > 1 && !hasAZP {
		return invalid()
	}
	if json.Unmarshal(c["iat"], &out.IssuedAt) != nil || json.Unmarshal(c["exp"], &out.ExpiresAt) != nil {
		return invalid()
	}
	now := time.Now().Unix()
	if out.IssuedAt <= 0 || out.IssuedAt > now+60 || out.ExpiresAt <= now || out.ExpiresAt < out.IssuedAt {
		return invalid()
	}
	switch purpose {
	case upstreamIDToken:
		if raw, exists := c["auth_time"]; exists {
			if json.Unmarshal(raw, &out.AuthTime) != nil || out.AuthTime <= 0 || out.AuthTime > now+60 || out.AuthTime > out.IssuedAt+60 {
				return invalid()
			}
		}
		n, ok := str("nonce")
		if !ok || nonce == "" || n != nonce || out.Subject == "" {
			return invalid()
		}
	case upstreamLogoutToken:
		if _, ok := c["nonce"]; ok {
			return invalid()
		}
		if out.IssuedAt < now-300 || out.JWTID == "" || len(out.JWTID) > 512 || out.Subject == "" && out.SessionID == "" {
			return invalid()
		}
		var events map[string]json.RawMessage
		if json.Unmarshal(c["events"], &events) != nil {
			return invalid()
		}
		var event map[string]json.RawMessage
		if v, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok || json.Unmarshal(v, &event) != nil || event == nil {
			return invalid()
		}
	default:
		return invalid()
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return invalid()
	}
	keys, e := a.upstreamSigningKeys(ctx, p, kid)
	if e != nil {
		return out, e
	}
	for _, k := range keys {
		if (kid == "" || kid == k.kid) && (k.alg == "" || k.alg == alg) && verifyUpstreamSignature(alg, k.key, []byte(parts[0]+"."+parts[1]), sig) {
			return out, nil
		}
	}
	return invalid()
}
func verifyUpstreamSignature(alg string, key crypto.PublicKey, msg, sig []byte) bool {
	var hash crypto.Hash
	var digest []byte
	switch {
	case strings.HasSuffix(alg, "256"):
		hash = crypto.SHA256
		v := sha256.Sum256(msg)
		digest = v[:]
	case strings.HasSuffix(alg, "384"):
		hash = crypto.SHA384
		v := sha512.Sum384(msg)
		digest = v[:]
	case strings.HasSuffix(alg, "512"):
		hash = crypto.SHA512
		v := sha512.Sum512(msg)
		digest = v[:]
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "RS") {
			return rsa.VerifyPKCS1v15(k, hash, digest, sig) == nil
		}
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(k, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}) == nil
		}
	case *ecdsa.PublicKey:
		expected := map[string]int{"ES256": 256, "ES384": 384, "ES512": 521}[alg]
		if k.Curve.Params().BitSize != expected {
			return false
		}
		n := (expected + 7) / 8
		if len(sig) != 2*n {
			return false
		}
		return ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(k, msg, sig)
	}
	return false
}
func (a *App) upstreamSigningKeys(ctx context.Context, p db.UpstreamProvider, kid string) ([]upstreamKey, error) {
	cache := &a.upstreamKeys
	identity := fmt.Sprintf("%d\x00%d\x00%s\x00%s\x00%s", p.ID, p.Revision, p.Issuer, p.JwksUrl, p.SigningAlg)
	for {
		if ctx.Err() != nil {
			return nil, errUpstreamJWKSUnavailable
		}
		cache.mu.Lock()
		if cache.entries == nil {
			cache.entries = map[string]upstreamKeyEntry{}
		}
		now := time.Now()
		entry, exists := cache.entries[identity]
		has := false
		for _, k := range entry.keys {
			if kid == "" || k.kid == kid {
				has = true
			}
		}
		if now.Sub(entry.fetched) < upstreamJWKSTTL && has {
			cache.mu.Unlock()
			return entry.keys, nil
		}
		if entry.inflight != nil {
			done := entry.inflight
			cache.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, errUpstreamJWKSUnavailable
			}
		}
		if now.Sub(entry.attempted) < 10*time.Second {
			cache.mu.Unlock()
			return nil, errUpstreamJWKSUnavailable
		}
		// Never evict active fetches: their waiters must share the same completion.
		if !exists && len(cache.entries) >= 256 {
			for key, v := range cache.entries {
				if v.inflight == nil && now.Sub(v.attempted) > upstreamJWKSTTL {
					delete(cache.entries, key)
				}
			}
			if len(cache.entries) >= 256 {
				for key, v := range cache.entries {
					if v.inflight == nil {
						delete(cache.entries, key)
						break
					}
				}
			}
			if len(cache.entries) >= 256 {
				cache.mu.Unlock()
				return nil, errUpstreamJWKSUnavailable
			}
		}
		entry.attempted = now
		entry.inflight = make(chan struct{})
		cache.entries[identity] = entry
		cache.mu.Unlock()
		keys, err := a.fetchUpstreamSigningKeys(ctx, p)
		cache.mu.Lock()
		completed := entry
		completed.inflight = nil
		if err == nil {
			completed.keys = keys
			completed.fetched = time.Now()
		}
		cache.entries[identity] = completed
		close(entry.inflight)
		cache.mu.Unlock()
		return keys, err
	}
}

func (a *App) fetchUpstreamSigningKeys(ctx context.Context, p db.UpstreamProvider) ([]upstreamKey, error) {
	if p.JwksUrl == "" || validateLogoutURI(p.JwksUrl) != nil {
		return nil, errUpstreamJWKSUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, p.JwksUrl, nil)
	if e != nil {
		return nil, errUpstreamJWKSUnavailable
	}
	client := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if a.HTTP != nil {
		client.Transport = a.HTTP.Transport
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, errUpstreamJWKSUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errUpstreamJWKSUnavailable
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, 1048577))
	if e != nil || len(body) > 1048576 {
		return nil, errUpstreamJWKSUnavailable
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if strictJSON(body, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 100 {
		return nil, errUpstreamJWKSUnavailable
	}
	var keys []upstreamKey
	for _, raw := range set.Keys {
		for _, alg := range strings.Fields(p.SigningAlg) {
			if !supportedUpstreamAlg(alg) {
				continue
			}
			if k, ok := parseUpstreamJWK(raw, alg); ok {
				keys = append(keys, k)
			}
		}
	}
	if len(keys) == 0 {
		return nil, errUpstreamJWKSUnavailable
	}
	return keys, nil
}
func parseUpstreamJWK(raw []byte, alg string) (upstreamKey, bool) {
	var j struct {
		Kty, Kid, Alg, Use, Crv, N, E, X, Y string
		KeyOps                              []string `json:"key_ops"`
	}
	if json.Unmarshal(raw, &j) != nil || j.Use != "" && j.Use != "sig" || j.Alg != "" && j.Alg != alg {
		return upstreamKey{}, false
	}
	if j.KeyOps != nil {
		ok := false
		for _, op := range j.KeyOps {
			if op == "verify" {
				ok = true
			}
		}
		if !ok {
			return upstreamKey{}, false
		}
	}
	decode := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }
	k := upstreamKey{kid: j.Kid, alg: j.Alg}
	switch j.Kty {
	case "RSA":
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
			return k, false
		}
		n := new(big.Int).SetBytes(decode(j.N))
		eb := decode(j.E)
		if len(eb) == 0 || len(eb) > 4 || n.BitLen() < 2048 || n.BitLen() > 8192 {
			return k, false
		}
		e := new(big.Int).SetBytes(eb).Int64()
		if e < 3 || e > 2147483647 || e%2 == 0 {
			return k, false
		}
		k.key = &rsa.PublicKey{N: n, E: int(e)}
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			if alg != "ES256" {
				return k, false
			}
			curve = elliptic.P256()
		case "P-384":
			if alg != "ES384" {
				return k, false
			}
			curve = elliptic.P384()
		case "P-521":
			if alg != "ES512" {
				return k, false
			}
			curve = elliptic.P521()
		default:
			return k, false
		}
		xb, yb := decode(j.X), decode(j.Y)
		size := (curve.Params().BitSize + 7) / 8
		if len(xb) != size || len(yb) != size {
			return k, false
		}
		x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		if !curve.IsOnCurve(x, y) {
			return k, false
		}
		k.key = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	case "OKP":
		x := decode(j.X)
		if alg != "EdDSA" || j.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
			return k, false
		}
		k.key = ed25519.PublicKey(x)
	default:
		return k, false
	}
	return k, true
}
