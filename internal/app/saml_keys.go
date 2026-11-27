package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
	"math/big"
	"time"
)

func (a *App) samlKeySeal(client ids.ClientID, ref string, data []byte, open bool) ([]byte, error) {
	c, e := a.mfaCipher()
	if e != nil {
		return nil, e
	}
	aad := []byte(fmt.Sprintf("guard:saml:signing:%d:%s", client, ref))
	if open {
		if len(data) < c.NonceSize()+c.Overhead() {
			return nil, errors.New("invalid SAML private key")
		}
		return c.Open(nil, data[:c.NonceSize()], data[c.NonceSize():], aad)
	}
	n := make([]byte, c.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return c.Seal(n, n, data, aad), nil
}
func (a *App) createSAMLKey(ctx context.Context, q *db.Queries, client ids.ClientID) error {
	key, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Guard SAML signing"}, NotBefore: now.Add(-time.Minute), NotAfter: time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return e
	}
	ref := security.Token()
	sealed, e := a.samlKeySeal(client, ref, x509.MarshalPKCS1PrivateKey(key), false)
	if e != nil {
		return e
	}
	_, e = q.CreateSAMLKey(ctx, db.CreateSAMLKeyParams{ClientID: client, KeyRef: ref, PrivateKey: base64.RawURLEncoding.EncodeToString(sealed), Certificate: der})
	return e
}
func (a *App) samlSigningKey(ctx context.Context, q *db.Queries, client ids.ClientID) (*rsa.PrivateKey, *x509.Certificate, error) {
	keys, e := q.SAMLKeys(ctx, client)
	if e != nil {
		return nil, nil, e
	}
	for _, k := range keys {
		cert, e := x509.ParseCertificate(k.Certificate)
		if e != nil {
			return nil, nil, e
		}
		b, e := base64.RawURLEncoding.DecodeString(k.PrivateKey)
		if e != nil {
			return nil, nil, e
		}
		b, e = a.samlKeySeal(client, k.KeyRef, b, true)
		if e != nil {
			return nil, nil, e
		}
		key, e := x509.ParsePKCS1PrivateKey(b)
		return key, cert, e
	}
	return nil, nil, errors.New("SAML signing key unavailable")
}
func samlFingerprint(b []byte) string { h := sha256.Sum256(b); return fmt.Sprintf("%X", h) }
