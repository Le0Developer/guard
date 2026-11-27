package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type upstreamDiscovery struct {
	Issuer, AuthorizeURL, TokenURL, UserinfoURL, JWKSURL string
	Algorithms                                           []string
}

func validateUpstreamURL(raw string, issuer bool) error {
	if raw == "" || strings.ContainsAny(raw, "#*\\") || len(raw) > 2048 {
		return errors.New("invalid upstream URL")
	}
	if err := validateLogoutURI(raw); err != nil {
		return errors.New("invalid upstream URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (issuer && (u.RawQuery != "" || u.ForceQuery)) {
		return errors.New("invalid upstream issuer")
	}
	return nil
}
func (a *App) discoverUpstream(ctx context.Context, issuer string) (upstreamDiscovery, error) {
	return a.discoverUpstreamConfiguration(ctx, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", issuer)
}

func (a *App) discoverUpstreamConfiguration(ctx context.Context, configurationURL, expectedIssuer string) (upstreamDiscovery, error) {
	var d upstreamDiscovery
	fail := func() (upstreamDiscovery, error) {
		return upstreamDiscovery{}, adminInvalid("Unable to discover provider. Check the OIDC configuration URL and provider metadata.")
	}
	if validateUpstreamURL(configurationURL, false) != nil || expectedIssuer != "" && validateUpstreamURL(expectedIssuer, true) != nil {
		return fail()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", configurationURL, nil)
	if err != nil {
		return fail()
	}
	client := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if a.HTTP != nil {
		client.Transport = a.HTTP.Transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail()
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fail()
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return fail()
	}
	var m struct {
		Issuer        string   `json:"issuer"`
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		Userinfo      string   `json:"userinfo_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		Algorithms    []string `json:"id_token_signing_alg_values_supported"`
	}
	if strictJSON(body, &m) != nil || validateUpstreamURL(m.Issuer, true) != nil || expectedIssuer != "" && m.Issuer != expectedIssuer || len(m.Algorithms) == 0 {
		return fail()
	}
	for _, endpoint := range []string{m.Authorization, m.Token, m.Userinfo, m.JWKS} {
		if validateUpstreamURL(endpoint, false) != nil {
			return fail()
		}
	}
	d = upstreamDiscovery{m.Issuer, m.Authorization, m.Token, m.Userinfo, m.JWKS, m.Algorithms}
	return d, nil
}
