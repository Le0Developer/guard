// Package samlidp implements Guard's deliberately narrow SAML IdP profile.
package samlidp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

const Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
const Email = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
const Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
const protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
const assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

type ACS struct {
	URL     string
	Index   int
	Default bool
}
type Config struct {
	Issuer, SSO, NameID string
	ACS                 []ACS
	RequireSignature    bool
	Certificates        []*x509.Certificate
}
type Request struct {
	ID, ACS, RelayState, NameID, Error string
	Force, Passive, AllowCreate        bool
	Received                           time.Time
}

var invalid = errors.New("invalid or unsupported SAML request")

func ParseRedirect(raw string, c Config, now time.Time) (Request, error) {
	out := Request{Received: now}
	if len(raw) > 32768 {
		return out, invalid
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return out, invalid
	}
	original := map[string]string{}
	for _, part := range strings.Split(raw, "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return out, invalid
		}
		name, e := url.QueryUnescape(k)
		if e != nil || name != k {
			return out, invalid
		}
		original[k] = v
	}
	for k, v := range q {
		if len(v) != 1 || k != "SAMLRequest" && k != "RelayState" && k != "SigAlg" && k != "Signature" {
			return out, invalid
		}
	}
	if q.Get("SAMLRequest") == "" || len(q.Get("RelayState")) > 80 {
		return out, invalid
	}
	out.RelayState = q.Get("RelayState")
	if c.RequireSignature || q.Has("Signature") || q.Has("SigAlg") {
		if q.Get("SigAlg") != rsaSHA256 || q.Get("Signature") == "" {
			return out, invalid
		}
		signed := "SAMLRequest=" + original["SAMLRequest"]
		if q.Has("RelayState") {
			signed += "&RelayState=" + original["RelayState"]
		}
		signed += "&SigAlg=" + original["SigAlg"]
		sig, e := base64.StdEncoding.DecodeString(q.Get("Signature"))
		if e != nil {
			return out, invalid
		}
		h := sha256.Sum256([]byte(signed))
		valid := false
		for _, cert := range c.Certificates {
			key, ok := cert.PublicKey.(*rsa.PublicKey)
			if ok && key.N.BitLen() >= 2048 && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) && rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) == nil {
				valid = true
				break
			}
		}
		if !valid {
			return out, invalid
		}
	}
	compressed, err := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if err != nil {
		return out, invalid
	}
	z := flate.NewReader(bytes.NewReader(compressed))
	defer z.Close()
	b, err := io.ReadAll(io.LimitReader(z, 128*1024+1))
	if err != nil || len(b) > 128*1024 {
		return out, invalid
	}
	// Strict token walk prevents ignored XML from changing the meaning of a request.
	dec := xml.NewDecoder(bytes.NewReader(b))
	depth := 0
	roots := 0
	issuerCount := 0
	policyCount := 0
	ids := map[string]bool{}
	var root xml.StartElement
	var issuer strings.Builder
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, invalid
		}
		switch t := tok.(type) {
		case xml.Directive:
			return out, invalid
		case xml.ProcInst:
			if t.Target != "xml" {
				return out, invalid
			}
		case xml.StartElement:
			depth++
			if depth > 32 {
				return out, invalid
			}
			seen := map[xml.Name]bool{}
			for _, a := range t.Attr {
				if seen[a.Name] {
					return out, invalid
				}
				seen[a.Name] = true
				if a.Name.Local == "ID" {
					if a.Value == "" || ids[a.Value] {
						return out, invalid
					}
					ids[a.Value] = true
				}
			}
			if depth == 1 {
				roots++
				if roots != 1 || t.Name != (xml.Name{Space: protocolNS, Local: "AuthnRequest"}) {
					return out, invalid
				}
				root = t
			} else if depth == 2 && t.Name == (xml.Name{Space: assertionNS, Local: "Issuer"}) {
				issuerCount++
				if issuerCount > 1 {
					return out, invalid
				}
			} else if depth == 2 && t.Name == (xml.Name{Space: protocolNS, Local: "NameIDPolicy"}) {
				policyCount++
				if policyCount > 1 {
					return out, invalid
				}
				for _, a := range t.Attr {
					if a.Name.Local == "Format" {
						out.NameID = a.Value
					}
					if a.Name.Local == "SPNameQualifier" && a.Value != "" {
						out.Error = "InvalidNameIDPolicy"
					}
					if a.Name.Local == "AllowCreate" {
						v, e := strconv.ParseBool(a.Value)
						if e != nil {
							return out, invalid
						}
						out.AllowCreate = v
					}
				}
			} else if depth == 2 && t.Name == (xml.Name{Space: protocolNS, Local: "RequestedAuthnContext"}) {
				out.Error = "NoAuthnContext"
			} else if depth == 3 && out.Error == "NoAuthnContext" && t.Name.Space == assertionNS && (t.Name.Local == "AuthnContextClassRef" || t.Name.Local == "AuthnContextDeclRef") {
			} else {
				return out, invalid
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 2 && issuerCount == 1 && policyCount == 0 {
				issuer.Write(t)
			} else if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return out, invalid
			}
		}
	}
	if roots != 1 || depth != 0 || issuerCount != 1 || issuer.String() != c.Issuer {
		return out, invalid
	}
	attrs := map[string]string{}
	for _, a := range root.Attr {
		if a.Name.Space == "" {
			attrs[a.Name.Local] = a.Value
		}
	}
	out.ID = attrs["ID"]
	if len(out.ID) > 256 || out.ID == "" || attrs["Version"] != "2.0" || attrs["Destination"] != c.SSO {
		return out, invalid
	}
	issued, e := time.Parse(time.RFC3339Nano, attrs["IssueInstant"])
	if e != nil || issued.Before(now.Add(-5*time.Minute)) || issued.After(now.Add(time.Minute)) {
		return out, invalid
	}
	for _, name := range []string{"ForceAuthn", "IsPassive"} {
		if v, ok := attrs[name]; ok {
			b, e := strconv.ParseBool(v)
			if e != nil {
				return out, invalid
			}
			if name == "ForceAuthn" {
				out.Force = b
			} else {
				out.Passive = b
			}
		}
	}
	if v := attrs["ProtocolBinding"]; v != "" && v != saml.HTTPPostBinding {
		return out, invalid
	}
	if _, ok := attrs["AttributeConsumingServiceIndex"]; ok {
		return out, invalid
	}
	acs, hasURL := attrs["AssertionConsumerServiceURL"]
	index, hasIndex := attrs["AssertionConsumerServiceIndex"]
	if hasURL && hasIndex {
		return out, invalid
	}
	for _, ep := range c.ACS {
		match := !hasURL && !hasIndex && ep.Default || hasURL && ep.URL == acs
		if hasIndex {
			n, e := strconv.Atoi(index)
			match = e == nil && n >= 0 && n == ep.Index
		}
		if match {
			out.ACS = ep.URL
			break
		}
	}
	if out.ACS == "" {
		return out, invalid
	}
	if out.NameID == "" || out.NameID == Unspecified {
		out.NameID = c.NameID
	}
	if out.NameID != c.NameID {
		out.Error = "InvalidNameIDPolicy"
	}
	return out, nil
}
