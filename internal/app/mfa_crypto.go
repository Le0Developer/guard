package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/ids"
	"strings"
	"time"
)

func mfaRandom() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func mfaHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func (a *App) mfaCipher() (cipher.AEAD, error) {
	b, e := base64.RawURLEncoding.DecodeString(a.Config.MFAEncryptionKey)
	if e != nil || len(b) != 32 {
		return nil, errors.New("MFA_ENCRYPTION_KEY must be a base64url 32-byte key")
	}
	c, e := aes.NewCipher(b)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(c)
}
func (a *App) mfaSeal(id ids.UserID, s string) (string, error) {
	c, e := a.mfaCipher()
	if e != nil {
		return "", e
	}
	n := make([]byte, c.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(c.Seal(n, n, []byte(s), []byte(fmt.Sprintf("guard:totp:%d", id)))), nil
}
func (a *App) mfaOpen(id ids.UserID, s string) (string, error) {
	c, e := a.mfaCipher()
	if e != nil {
		return "", e
	}
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) < c.NonceSize()+c.Overhead() {
		return "", errors.New("invalid authenticator secret")
	}
	v, e := c.Open(nil, b[:c.NonceSize()], b[c.NonceSize():], []byte(fmt.Sprintf("guard:totp:%d", id)))
	return string(v), e
}
func mfaTOTP(secret string, step int64) string {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	h := hmac.New(sha1.New, key)
	h.Write(b[:])
	s := h.Sum(nil)
	o := s[len(s)-1] & 15
	n := binary.BigEndian.Uint32(s[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}
func mfaStep(secret, code string, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	step := time.Now().Unix() / 30
	for _, n := range []int64{step, step - 1, step + 1} {
		if n > last && subtle.ConstantTimeCompare([]byte(mfaTOTP(secret, n)), []byte(code)) == 1 {
			return n, true
		}
	}
	return 0, false
}

func mfaRecoveryHash(id ids.UserID, code string) string {
	normalized := strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
			return -1
		}
		return r
	}, strings.ToLower(code))
	return mfaHash(fmt.Sprintf("%d:%s", id, normalized))
}
