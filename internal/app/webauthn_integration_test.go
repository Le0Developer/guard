package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A small software authenticator exercises real go-webauthn verification without
// introducing a test dependency or requiring a physical key on CI.
func TestWebAuthnEnrollmentAndSignedLogin(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash("manage-session"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	owner := &identity{User: u, Session: s}
	form := func(path string, values url.Values) *http.Request {
		r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r.WithContext(context.WithValue(r.Context(), identityKey{}, owner))
	}
	w := httptest.NewRecorder()
	a.mfaEnrollStart(w, form("/security/keys/start", url.Values{"name": {"Software test key"}}))
	if w.Code != 200 {
		t.Fatalf("begin enroll %d %s", w.Code, w.Body.String())
	}
	var begin struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
		Ceremony string `json:"ceremony"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	rand.Read(credID)
	enc := base64.RawURLEncoding.EncodeToString
	rp := sha256.Sum256([]byte("localhost"))
	authData := append([]byte{}, rp[:]...)
	authData = append(authData, 0x45, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credID)))
	authData = append(authData, credID...)
	// COSE EC2/P-256 key: {1:2,3:-7,-1:1,-2:x,-3:y}.
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	cose = append(cose, private.X.FillBytes(make([]byte, 32))...)
	cose = append(cose, 0x22, 0x58, 0x20)
	cose = append(cose, private.Y.FillBytes(make([]byte, 32))...)
	authData = append(authData, cose...)
	// CBOR attestation {fmt:"none",attStmt:{},authData:bytes}.
	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x58, byte(len(authData))}
	att = append(att, authData...)
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": begin.PublicKey.Challenge, "origin": a.Config.Domain, "crossOrigin": false})
	payload, _ := json.Marshal(map[string]any{"id": enc(credID), "rawId": enc(credID), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"attestationObject": enc(att), "clientDataJSON": enc(clientData), "transports": []string{"usb"}}})
	w = httptest.NewRecorder()
	a.mfaEnrollFinish(w, form("/security/keys/finish", url.Values{"ceremony": {begin.Ceremony}, "credential": {string(payload)}}))
	if w.Code != 200 {
		t.Fatalf("finish enroll %d %s", w.Code, w.Body.String())
	}
	credentials, err := a.Q.WebauthnCredentialsByUserId(ctx, u.ID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credential not persisted: %v", err)
	}
	u, err = a.Q.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, loginRaw, pending := mfaTestPending(t, a, u)
	r := mfaTestRequest(loginRaw, pending, "", "")
	w = httptest.NewRecorder()
	a.mfaAuthStart(w, r)
	if w.Code != 200 {
		t.Fatalf("begin login %d %s", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	clientData, _ = json.Marshal(map[string]any{"type": "webauthn.get", "challenge": begin.PublicKey.Challenge, "origin": a.Config.Domain, "crossOrigin": false})
	clientHash := sha256.Sum256(clientData)
	assertion := append([]byte{}, rp[:]...)
	assertion = append(assertion, 0x05, 0, 0, 0, 1)
	signed := append(append([]byte{}, assertion...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"id": enc(credID), "rawId": enc(credID), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"authenticatorData": enc(assertion), "clientDataJSON": enc(clientData), "signature": enc(signature), "userHandle": enc(u.WebauthnUserID)}})
	finish := func() *http.Request {
		r := httptest.NewRequest("POST", "/login/mfa/key/finish", strings.NewReader(url.Values{"ceremony": {begin.Ceremony}, "credential": {string(payload)}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "login_session", Value: loginRaw})
		r.AddCookie(&http.Cookie{Name: "mfa_pending", Value: pending})
		return r
	}
	w = httptest.NewRecorder()
	a.mfaAuthFinish(w, finish())
	if w.Code != 200 {
		t.Fatalf("signed login %d %s", w.Code, w.Body.String())
	}
	var sessionRaw string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session" {
			sessionRaw = cookie.Value
		}
	}
	if sessionRaw == "" {
		t.Fatal("no browser session after key verification")
	}
	if _, err = a.Q.SessionByTokenHash(ctx, security.Hash(sessionRaw)); err != nil {
		t.Fatal(err)
	}
	credentials, err = a.Q.WebauthnCredentialsByUserId(ctx, u.ID)
	if err != nil || credentials[0].SignCount != 1 {
		t.Fatalf("counter not updated %v", err)
	}
	replay := httptest.NewRecorder()
	a.mfaAuthFinish(replay, finish())
	if replay.Code == 200 {
		t.Fatal("accepted signed response replay")
	}
}
