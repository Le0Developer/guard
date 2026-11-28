package app

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/samlidp"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func samlAdminPath(id ids.ClientID) string { return fmt.Sprintf("/admin/clients/%d/saml", id) }
func (a *App) adminSAML(w http.ResponseWriter, r *http.Request, _ *identity) error {
	id, e := adminID[ids.ClientID](r.PathValue("id"))
	if e != nil {
		return e
	}
	c, e := adminClient(r.Context(), a.Q, id, false)
	if e != nil {
		return e
	}
	if c.ClientType != "Saml" {
		return adminMissing()
	}
	cfg, e := a.Q.GetSAMLConfig(r.Context(), id)
	if e != nil && !notFound(e) {
		return e
	}
	if cfg.NameIDFormat == "" {
		cfg.NameIDFormat = samlidp.Persistent
	}
	eps, e := a.Q.SAMLACS(r.Context(), id)
	if e != nil {
		return e
	}
	var acs strings.Builder
	defaultIndex := int32(0)
	for _, ep := range eps {
		fmt.Fprintf(&acs, "%d %s\n", ep.EndpointIndex, ep.Url)
		if ep.IsDefault {
			defaultIndex = ep.EndpointIndex
		}
	}
	keys, e := a.Q.SAMLKeys(r.Context(), id)
	if e != nil {
		return e
	}
	type keyView struct {
		ID          ids.SAMLSigningKeyID
		Fingerprint string
	}
	views := []keyView{}
	for _, k := range keys {
		views = append(views, keyView{k.ID, samlFingerprint(k.Certificate)})
	}
	certs, e := a.Q.SAMLSPCertificates(r.Context(), id)
	if e != nil {
		return e
	}
	var certificates strings.Builder
	for _, cert := range certs {
		certificates.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate}))
	}
	a.page(w, r, "SAML configuration", adminSAMLTemplate, map[string]any{"Client": c, "Config": cfg, "ACS": acs.String(), "DefaultIndex": defaultIndex, "Keys": views, "Certificates": certificates.String(), "Base": a.samlBase(c), "Action": samlAdminPath(id)})
	return nil
}
func (a *App) adminSAMLWrite(w http.ResponseWriter, r *http.Request, actor *identity) error {
	id, e := adminID[ids.ClientID](r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = adminRequired(r.PostForm.Get("entity_id"), "SP entity ID", 2048); e != nil {
		return e
	}
	format := r.PostForm.Get("name_id_format")
	if format != samlidp.Persistent && format != samlidp.Email {
		return adminInvalid("Choose a supported NameID format.")
	}
	if launch := r.PostForm.Get("launch_url"); launch != "" {
		if e = validateLogoutURI(launch); e != nil {
			return adminInvalid("Enter an HTTPS application login URL, or HTTP loopback URL.")
		}
	}
	e = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries, change *adminAuditChange) error {
		c, e := adminClient(r.Context(), q, id, true)
		if e != nil {
			return e
		}
		if c.ClientType != "Saml" {
			return adminMissing()
		}
		if e = change.capture(r.Context(), q, id); e != nil {
			return e
		}
		lines := strings.Split(strings.TrimSpace(r.PostForm.Get("acs")), "\n")
		if len(lines) > 32 {
			return adminInvalid("Register at most 32 ACS endpoints.")
		}
		eps := []db.CreateSAMLACSParams{}
		seenIndex := map[int32]bool{}
		seenURL := map[string]bool{}
		def, e := strconv.ParseInt(r.PostForm.Get("default_index"), 10, 32)
		if e != nil || def < 0 {
			return adminInvalid("Enter a valid default ACS index.")
		}
		foundDefault := false
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return adminInvalid("Enter one ACS per line: index followed by URL.")
			}
			index, e := strconv.ParseInt(fields[0], 10, 32)
			if e != nil || index < 0 || seenIndex[int32(index)] || seenURL[fields[1]] {
				return adminInvalid("ACS indices and URLs must be unique.")
			}
			if e = validateLogoutURI(fields[1]); e != nil {
				return adminInvalid("ACS requires an exact HTTPS URL, or HTTP loopback URL.")
			}
			seenIndex[int32(index)] = true
			seenURL[fields[1]] = true
			isDefault := index == def
			foundDefault = foundDefault || isDefault
			eps = append(eps, db.CreateSAMLACSParams{ClientID: id, EndpointIndex: int32(index), Url: fields[1], IsDefault: isDefault})
		}
		if !foundDefault {
			return adminInvalid("The default ACS index must be registered.")
		}
		certs := [][]byte{}
		remaining := []byte(r.PostForm.Get("certificates"))
		if len(remaining) > 64*1024 {
			return adminInvalid("SP certificates exceed 64 KiB.")
		}
		for len(strings.TrimSpace(string(remaining))) > 0 {
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" {
				return adminInvalid("Enter PEM encoded SP signing certificates.")
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				return adminInvalid("Invalid SP signing certificate.")
			}
			key, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok || key.N.BitLen() < 2048 || !cert.NotAfter.After(time.Now()) || cert.NotBefore.After(time.Now()) {
				return adminInvalid("Use a currently valid RSA signing certificate with at least 2048 bits.")
			}
			certs = append(certs, block.Bytes)
			remaining = rest
			if len(certs) > 8 {
				return adminInvalid("Register at most eight SP signing certificates.")
			}
		}
		required := r.PostForm.Has("require_signature")
		if required && len(certs) == 0 {
			return adminInvalid("Signed requests require an SP certificate.")
		}
		_, e = q.SaveSAMLConfig(r.Context(), db.SaveSAMLConfigParams{ClientID: id, EntityID: r.PostForm.Get("entity_id"), NameIDFormat: r.PostForm.Get("name_id_format"), RequireSignature: required, LaunchUrl: r.PostForm.Get("launch_url")})
		if e != nil {
			return e
		}
		if e = q.DeleteSAMLACS(r.Context(), id); e != nil {
			return e
		}
		for _, ep := range eps {
			if e = q.CreateSAMLACS(r.Context(), ep); e != nil {
				return e
			}
		}
		if e = q.DeleteSAMLSPCertificates(r.Context(), id); e != nil {
			return e
		}
		for _, cert := range certs {
			if e = q.CreateSAMLSPCertificate(r.Context(), db.CreateSAMLSPCertificateParams{ClientID: id, Certificate: cert}); e != nil {
				return e
			}
		}
		keys, e := q.SAMLKeys(r.Context(), id)
		if e != nil {
			return e
		}
		if len(keys) == 0 {
			if e = a.createSAMLKey(r.Context(), q, id); e != nil {
				return e
			}
		}
		return nil // adminMutation records the complete SAML configuration diff.
	})
	if e != nil {
		return e
	}
	adminSaved(w, r, samlAdminPath(id))
	return nil
}
func (a *App) adminSAMLCertificate(w http.ResponseWriter, r *http.Request, _ *identity) error {
	id, e := adminID[ids.ClientID](r.PathValue("id"))
	if e != nil {
		return e
	}
	c, e := adminClient(r.Context(), a.Q, id, false)
	if e != nil {
		return e
	}
	if c.ClientType != "Saml" {
		return adminMissing()
	}
	kid, e := adminID[ids.SAMLSigningKeyID](r.PathValue("key_id"))
	if e != nil {
		return e
	}
	keys, e := a.Q.SAMLKeys(r.Context(), id)
	if e != nil {
		return e
	}
	for _, k := range keys {
		if k.ID == kid {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="guard-saml-signing.pem"`)
			_, e = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.Certificate}))
			return e
		}
	}
	return adminMissing()
}
