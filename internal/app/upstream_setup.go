package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/le0developer/guard/internal/db"
)

func (a *App) configureUpstream(r *http.Request, p *db.UpstreamProvider, old db.UpstreamProvider, fresh bool) error {
	p.ConfigurationMode = r.FormValue("configuration_mode")
	if p.ConfigurationMode == "" {
		p.ConfigurationMode = old.ConfigurationMode
	}
	if p.ConfigurationMode == "" {
		p.ConfigurationMode = "oidc_discovery"
	}
	p.ClientAuthMethod = "client_secret_basic"
	p.SubjectField, p.EmailField, p.EmailVerifiedField = "sub", "email", "email_verified"
	p.DiscoveryUrl = ""
	switch p.ConfigurationMode {
	case "oidc_discovery":
		p.DiscoveryUrl = r.FormValue("discovery_url")
		expectedIssuer := ""
		if p.DiscoveryUrl == "" {
			if p.Issuer != "" {
				p.DiscoveryUrl = strings.TrimRight(p.Issuer, "/") + "/.well-known/openid-configuration"
				expectedIssuer = p.Issuer
			} else {
				p.DiscoveryUrl = old.DiscoveryUrl
			}
		}
		if validateUpstreamURL(p.DiscoveryUrl, false) != nil {
			return adminInvalid("Enter an absolute OIDC configuration URL, including the path to the JSON document.")
		}
		if fresh || p.ConfigurationMode != old.ConfigurationMode || p.DiscoveryUrl != old.DiscoveryUrl || r.FormValue("refresh_discovery") != "" {
			d, err := a.discoverUpstreamConfiguration(r.Context(), p.DiscoveryUrl, expectedIssuer)
			if err != nil {
				return err
			}
			algorithms := []string{}
			for _, alg := range strings.Fields(automaticUpstreamAlgorithms) {
				for _, advertised := range d.Algorithms {
					if alg == advertised {
						algorithms = append(algorithms, alg)
						break
					}
				}
			}
			if len(algorithms) == 0 {
				return adminInvalid("The provider does not advertise any supported signing algorithm.")
			}
			p.SigningAlg = strings.Join(algorithms, " ")
			p.Issuer, p.AuthorizeUrl, p.TokenUrl, p.UserinfoUrl, p.JwksUrl = d.Issuer, d.AuthorizeURL, d.TokenURL, d.UserinfoURL, d.JWKSURL
		} else {
			p.Issuer = old.Issuer
		}
	case "oidc_manual", "oauth2":
		if p.ConfigurationMode == "oidc_manual" {
			p.SigningAlg = automaticUpstreamAlgorithms
		}
		p.AuthorizeUrl, p.TokenUrl, p.UserinfoUrl = r.FormValue("authorize_url"), r.FormValue("token_url"), r.FormValue("userinfo_url")
		for _, field := range []struct{ value, name string }{{p.AuthorizeUrl, "Authorization URL"}, {p.TokenUrl, "Token URL"}, {p.UserinfoUrl, "User info URL"}} {
			if validateUpstreamURL(field.value, false) != nil {
				return adminInvalid(field.name + " must be an absolute HTTPS URL (HTTP is allowed on loopback for development).")
			}
		}
		if p.ConfigurationMode == "oidc_manual" {
			p.JwksUrl = r.FormValue("jwks_url")
			if validateUpstreamURL(p.Issuer, true) != nil || validateUpstreamURL(p.JwksUrl, false) != nil {
				return adminInvalid("Manual OIDC requires a valid issuer identifier and JWKS URL.")
			}
		} else {
			p.Issuer, p.JwksUrl, p.SigningAlg = "", "", ""
			p.BackchannelLogoutEnabled = false
			p.SubjectField, p.EmailField, p.EmailVerifiedField = r.FormValue("subject_field"), r.FormValue("email_field"), r.FormValue("email_verified_field")
			if p.SubjectField == "" {
				p.SubjectField = "sub"
			}
			if p.EmailField == "" {
				p.EmailField = "email"
			}
			if p.EmailVerifiedField == "" {
				p.EmailVerifiedField = "email_verified"
			}
			for _, path := range []string{p.SubjectField, p.EmailField, p.EmailVerifiedField} {
				if !validProfilePath(path) {
					return adminInvalid("Profile field paths must contain non-empty, dot-separated keys or array indexes, up to 200 characters.")
				}
			}
		}
	default:
		return adminInvalid("Choose OIDC discovery, manual OIDC, or OAuth2 setup.")
	}
	if p.ConfigurationMode != "oauth2" {
		if !strings.Contains(" "+p.Scopes+" ", " openid ") {
			return adminInvalid("OIDC scopes must include openid.")
		}
	}
	return nil
}

func validProfilePath(path string) bool {
	if path == "" || len(path) > 200 {
		return false
	}
	for _, key := range strings.Split(path, ".") {
		if key == "" || strings.ContainsAny(key, " \t\r\n") {
			return false
		}
	}
	return true
}

func profileField(raw json.RawMessage, path string) json.RawMessage {
	for _, key := range strings.Split(path, ".") {
		if len(raw) == 0 {
			return nil
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) == nil {
			raw = object[key]
			continue
		}
		var array []json.RawMessage
		index, err := strconv.Atoi(key)
		if err != nil || index < 0 || json.Unmarshal(raw, &array) != nil || index >= len(array) {
			return nil
		}
		raw = array[index]
	}
	return raw
}

type upstreamProfile struct {
	Subject, Email string
	Verified       bool
}

func parseOAuth2Profile(raw []byte, p db.UpstreamProvider) (upstreamProfile, error) {
	var profile upstreamProfile
	var document json.RawMessage
	invalid := errors.New("profile must contain a stable subject and a verified email")
	if strictJSON(raw, &document) != nil {
		return profile, invalid
	}
	subject := profileField(document, p.SubjectField)
	if json.Unmarshal(subject, &profile.Subject) != nil {
		var number json.Number
		if len(subject) == 0 || subject[0] == '"' || json.Unmarshal(subject, &number) != nil {
			return profile, invalid
		}
		profile.Subject = number.String()
	}
	if json.Unmarshal(profileField(document, p.EmailField), &profile.Email) != nil || json.Unmarshal(profileField(document, p.EmailVerifiedField), &profile.Verified) != nil || !profile.Verified || profile.Subject == "" || len(profile.Subject) > 255 || !validEmail(profile.Email) {
		return upstreamProfile{}, invalid
	}
	return profile, nil
}
