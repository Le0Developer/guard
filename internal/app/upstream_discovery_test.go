package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamDiscoveryValidation(t *testing.T) {
	for _, s := range []string{"https://example.com?x=1", "https://example.com#", "http://example.com", "https://user@example.com", "https://example.com:*", "https://example.com\\x"} {
		if _, err := (&App{}).discoverUpstream(context.Background(), s); err == nil {
			t.Fatalf("accepted issuer %q", s)
		}
	}
}
func TestUpstreamDiscovery(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant/.well-known/openid-configuration" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","authorization_endpoint":"` + issuer + `/auth","token_endpoint":"` + issuer + `/token","userinfo_endpoint":"` + issuer + `/userinfo","jwks_uri":"` + issuer + `/keys","id_token_signing_alg_values_supported":["RS256"]}`))
	}))
	defer srv.Close()
	issuer = srv.URL + "/tenant"
	d, err := (&App{}).discoverUpstream(context.Background(), issuer)
	if err != nil || d.Issuer != issuer {
		t.Fatalf("discovery: %v", err)
	}
}

func TestUpstreamDiscoveryRejectsMetadata(t *testing.T) {
	for _, kind := range []string{"issuer", "endpoint", "algorithms", "redirect", "large"} {
		t.Run(kind, func(t *testing.T) {
			var issuer string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "redirect" {
					http.Redirect(w, r, "/other", 302)
					return
				}
				if kind == "large" {
					_, _ = w.Write([]byte(strings.Repeat(" ", 1<<20) + "{}"))
					return
				}
				iss := issuer
				endpoint := issuer + "/endpoint"
				algs := `["RS256"]`
				if kind == "issuer" {
					iss += "/"
				}
				if kind == "endpoint" {
					endpoint = "http://public.example/keys"
				}
				if kind == "algorithms" {
					algs = "null"
				}
				fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":%s}`, iss, endpoint, endpoint, endpoint, endpoint, algs)
			}))
			defer srv.Close()
			issuer = srv.URL
			if _, err := (&App{}).discoverUpstream(context.Background(), issuer); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
}

func TestUpstreamDiscoveryRejectsDuplicateMetadata(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":"https://other.example","issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`, issuer, issuer+"/auth", issuer+"/token", issuer+"/user", issuer+"/keys")
	}))
	defer srv.Close()
	issuer = srv.URL
	if _, err := (&App{}).discoverUpstream(context.Background(), issuer); err == nil {
		t.Fatal("accepted duplicate issuer")
	}
}

func TestUpstreamDiscoveryCustomTransport(t *testing.T) {
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`, issuer, issuer+"/auth", issuer+"/token", issuer+"/user", issuer+"/keys")
	}))
	defer srv.Close()
	issuer = srv.URL
	a := &App{HTTP: srv.Client()}
	if _, err := a.discoverUpstream(context.Background(), issuer); err != nil {
		t.Fatalf("trusted custom transport ignored: %v", err)
	}
}
