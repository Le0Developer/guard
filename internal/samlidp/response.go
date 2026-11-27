package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"sort"
	"time"
)

type ResponseInput struct {
	Issuer, Audience, Subject, SessionIndex, Error string
	Request                                        Request
	Now, AuthTime, SessionExpiry                   time.Time
	Attributes                                     map[string][]string
}

func randomID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return "_" + hex.EncodeToString(b[:])
}
func Response(in ResponseInput, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	if key == nil || cert == nil || in.Now.Before(cert.NotBefore) || !in.Now.Before(cert.NotAfter) {
		return nil, errors.New("no valid SAML signing key")
	}
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		return nil, err
	}
	ctx.IdAttribute = "ID"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err = ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	issuer := saml.Issuer{Value: in.Issuer}
	status := saml.StatusCode{Value: saml.StatusSuccess}
	if in.Error != "" {
		status = saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Responder", StatusCode: &saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:" + in.Error}}
	}
	response := saml.Response{ID: randomID(), Version: "2.0", IssueInstant: in.Now, Destination: in.Request.ACS, InResponseTo: in.Request.ID, Issuer: &issuer, Status: saml.Status{StatusCode: status}}
	root := response.Element()
	if in.Error == "" {
		expiry := in.Now.Add(2 * time.Minute)
		if in.SessionExpiry.Before(expiry) {
			expiry = in.SessionExpiry
		}
		if !expiry.After(in.Now) {
			return nil, errors.New("expired session")
		}
		assertion := saml.Assertion{ID: randomID(), Version: "2.0", IssueInstant: in.Now, Issuer: issuer,
			Subject:         &saml.Subject{NameID: &saml.NameID{Format: in.Request.NameID, Value: in.Subject}, SubjectConfirmations: []saml.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData: &saml.SubjectConfirmationData{Recipient: in.Request.ACS, InResponseTo: in.Request.ID, NotOnOrAfter: expiry}}}},
			Conditions:      &saml.Conditions{NotBefore: in.Now.Add(-time.Minute), NotOnOrAfter: expiry, AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: in.Audience}}}},
			AuthnStatements: []saml.AuthnStatement{{AuthnInstant: in.AuthTime, SessionIndex: in.SessionIndex, SessionNotOnOrAfter: &in.SessionExpiry, AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"}}}},
		}
		names := make([]string, 0, len(in.Attributes))
		for name := range in.Attributes {
			names = append(names, name)
		}
		sort.Strings(names)
		attrs := []saml.Attribute{}
		for _, name := range names {
			v := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"}
			for _, s := range in.Attributes[name] {
				if s != "" {
					v.Values = append(v.Values, saml.AttributeValue{Type: "xs:string", Value: s})
				}
			}
			if len(v.Values) > 0 {
				attrs = append(attrs, v)
			}
		}
		if len(attrs) > 0 {
			assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
		}
		el, err := ctx.SignEnveloped(assertion.Element())
		if err != nil {
			return nil, err
		}
		assertion.Signature = el.ChildElements()[len(el.ChildElements())-1]
		root.AddChild(assertion.Element())
	}
	signed, err := ctx.SignEnveloped(root)
	if err != nil {
		return nil, err
	}
	// The signature belongs immediately after Issuer, per the SAML schema.
	sig := signed.ChildElements()[len(signed.ChildElements())-1]
	response.Signature = sig
	rebuilt := response.Element()
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			rebuilt.AddChild(child.Copy())
		}
	}
	signed = rebuilt
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	b, err := doc.WriteToBytes()
	if len(b) > 256*1024 {
		return nil, errors.New("SAML response exceeds 256 KiB")
	}
	return b, err
}
