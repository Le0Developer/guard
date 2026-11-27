package samlidp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

func redirectQuery(xml string) string {
	var b bytes.Buffer
	z, _ := flate.NewWriter(&b, 9)
	z.Write([]byte(xml))
	z.Close()
	return url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(b.Bytes())}}.Encode()
}
func TestRedirectValidation(t *testing.T) {
	now := time.Now().UTC()
	cfg := Config{Issuer: "sp", SSO: "https://guard/sso", NameID: Persistent, ACS: []ACS{{URL: "https://sp/acs", Index: 0, Default: true}}}
	good := `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `" Destination="https://guard/sso"><s:Issuer>sp</s:Issuer></p:AuthnRequest>`
	r, err := ParseRedirect(redirectQuery(good), cfg, now)
	if err != nil || r.ACS != "https://sp/acs" || r.ID != "_request" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, xml := range []string{strings.Replace(good, "https://guard/sso", "https://evil", 1), strings.Replace(good, ">sp<", ">evil<", 1), strings.Replace(good, "Version=\"2.0\"", "Version=\"1.0\"", 1), strings.Replace(good, "</p:AuthnRequest>", `<p:AuthnRequest ID="_request"/></p:AuthnRequest>`, 1), `<!DOCTYPE x>` + good, strings.Replace(good, `Version="2.0"`, `AssertionConsumerServiceURL="https://evil/acs" Version="2.0"`, 1)} {
		if _, err := ParseRedirect(redirectQuery(xml), cfg, now); err == nil {
			t.Fatalf("accepted %s", xml)
		}
	}
	if _, err := ParseRedirect(redirectQuery(good)+"&SAMLRequest=duplicate", cfg, now); err == nil {
		t.Fatal("duplicate")
	}
	if _, err := ParseRedirect(redirectQuery(strings.Repeat("x", 128*1024+1)), cfg, now); err == nil {
		t.Fatal("oversize")
	}
	cfg.RequireSignature = true
	if _, err := ParseRedirect(redirectQuery(good), cfg, now); err == nil {
		t.Fatal("unsigned")
	}
}

func TestPrettyPrintedIssuer(t *testing.T) {
	now := time.Now().UTC()
	c := Config{Issuer: "sp", SSO: "https://guard/sso", NameID: Persistent, ACS: []ACS{{URL: "https://sp/acs", Default: true}}}
	xml := `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_pretty" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `" Destination="https://guard/sso">
  <s:Issuer>sp</s:Issuer>
  <p:NameIDPolicy Format="` + Persistent + `"/>
</p:AuthnRequest>`
	if _, e := ParseRedirect(redirectQuery(xml), c, now); e != nil {
		t.Fatal(e)
	}
}

func TestRedirectSignaturePolicy(t *testing.T) {
	now := time.Now().UTC()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{PublicKey: &key.PublicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	c := Config{Issuer: "sp", SSO: "https://guard/sso", NameID: Persistent, ACS: []ACS{{URL: "https://sp/acs", Default: true}}, RequireSignature: true, Certificates: []*x509.Certificate{cert}}
	xml := `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_signed" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `" Destination="https://guard/sso"><s:Issuer>sp</s:Issuer></p:AuthnRequest>`
	raw := redirectQuery(xml) + "&RelayState=keep%20encoded&SigAlg=" + url.QueryEscape(rsaSHA256)
	hash := sha256.Sum256([]byte(raw))
	sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if e != nil {
		t.Fatal(e)
	}
	signed := raw + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	if _, e := ParseRedirect(signed, c, now); e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{strings.Replace(signed, "keep%20encoded", "tampered", 1), strings.Replace(signed, url.QueryEscape(rsaSHA256), url.QueryEscape("rsa-sha1"), 1), signed + "&Signature=x"} {
		if _, e := ParseRedirect(q, c, now); e == nil {
			t.Fatal("accepted tampered signature")
		}
	}
	c.RequireSignature = false
	if _, e := ParseRedirect(signed+"bad", c, now); e == nil {
		t.Fatal("ignored optional invalid signature")
	}
}

func TestNameIDPolicyDefaultsDoNotAllowCreation(t *testing.T) {
	now := time.Now().UTC()
	c := Config{Issuer: "sp", SSO: "https://guard/sso", NameID: Persistent, ACS: []ACS{{URL: "https://sp/acs", Default: true}}}
	xml := `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_policy" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `" Destination="https://guard/sso"><s:Issuer>sp</s:Issuer></p:AuthnRequest>`
	req, e := ParseRedirect(redirectQuery(xml), c, now)
	if e != nil {
		t.Fatal(e)
	}
	if req.AllowCreate {
		t.Fatal("omitted policy must not authorize identifier creation")
	}
}
