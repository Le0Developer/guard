package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedResponse(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().UTC()
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &k.PublicKey, k)
	cert, _ := x509.ParseCertificate(der)
	b, err := Response(ResponseInput{Issuer: "https://guard/metadata", Audience: "sp", Request: Request{ID: "_req", ACS: "https://sp/acs", NameID: Persistent}, Subject: "opaque", SessionIndex: "index", Now: now, AuthTime: now, SessionExpiry: now.Add(time.Hour), Attributes: map[string][]string{"groups": {"a", "b"}}}, k, cert)
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("GUARD_SAML_INTEROP_DIR"); dir != "" {
		if e := os.WriteFile(filepath.Join(dir, "response.xml"), b, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(dir, "certificate.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(b); err != nil {
		t.Fatal(err)
	}
	v := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	v.IdAttribute = "ID"
	root, err := v.Validate(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	a := root.FindElement("./Assertion")
	if a == nil {
		t.Fatal("no assertion")
	}
	if _, err = v.Validate(a); err != nil {
		t.Fatal(err)
	}
	if root.SelectAttrValue("InResponseTo", "") != "_req" || a.FindElement("./Subject/NameID").Text() != "opaque" {
		t.Fatal("identity/correlation")
	}
}
