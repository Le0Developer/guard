package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSCIMProtocolURLValidation(t *testing.T) {
	for _, raw := range []string{"http://example.org/scim", "https://u:p@example.org/scim", "https://example.org/scim?q=x", "https://example.org/scim#x", "file:///scim", "https://example.org/../scim"} {
		if validateSCIMURL(raw) == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	for _, raw := range []string{"https://example.org/scim/v2", "http://127.0.0.1:1234/scim"} {
		if err := validateSCIMURL(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSCIMProtocolLookupPaginationAndAmbiguity(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Accept") != "application/scim+json" {
			t.Error("missing SCIM authentication/media type")
		}
		if r.URL.Path != "/base/Users" || r.URL.Query().Get("filter") != `externalId eq "guard:user:42"` {
			t.Errorf("wrong lookup: %s", r.URL)
		}
		calls++
		if r.URL.Query().Get("startIndex") == "1" {
			fmt.Fprint(w, `{"totalResults":2,"startIndex":1,"itemsPerPage":1,"Resources":[{"id":"one","externalId":"other"}]}`)
		} else {
			fmt.Fprint(w, `{"totalResults":2,"startIndex":2,"itemsPerPage":1,"Resources":[{"id":"two","externalId":"guard:user:42"}]}`)
		}
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL + "/base", secret: "secret", http: s.Client()}
	got, err := remote.lookup(context.Background(), "Users", "guard:user:42")
	if err != nil || got != "two" || calls != 2 {
		t.Fatalf("lookup %q %v calls=%d", got, err, calls)
	}
}

func TestSCIMProtocolPUTPreservesUnknownAttributes(t *testing.T) {
	var put map[string]any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(map[string]any{"id": "remote", "externalId": "guard:user:42", "userName": "old@example.org", "active": true, "locale": "de-DE", "meta": map[string]any{"version": "v1"}})
		case "PUT":
			json.NewDecoder(r.Body).Decode(&put)
			fmt.Fprint(w, `{"id":"remote"}`)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(500)
		}
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, secret: "secret", http: s.Client(), usePUT: true}
	_, err := remote.reconcile(context.Background(), "Users", "remote", map[string]any{"schemas": []string{scimUserSchema}, "externalId": "guard:user:42", "userName": "new@example.org", "active": true})
	if err != nil {
		t.Fatal(err)
	}
	if put["locale"] != "de-DE" || put["userName"] != "new@example.org" || put["meta"] != nil {
		t.Fatalf("wrong PUT: %#v", put)
	}
}

func TestSCIMProtocolPATCHAndRecovery(t *testing.T) {
	var patch map[string]any
	lookups, posts := 0, 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/Users":
			lookups++
			if posts > 0 {
				fmt.Fprint(w, `{"totalResults":1,"Resources":[{"id":"created","externalId":"stable"}]}`)
			} else {
				fmt.Fprint(w, `{"totalResults":0,"Resources":[]}`)
			}
		case r.Method == "POST":
			posts++
			w.WriteHeader(503) // created remotely, response lost
		case r.Method == "GET":
			fmt.Fprint(w, `{"id":"created","externalId":"stable","active":true}`)
		case r.Method == "PATCH":
			json.NewDecoder(r.Body).Decode(&patch)
			w.WriteHeader(204)
		default:
			w.WriteHeader(500)
		}
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, secret: "secret", http: s.Client()}
	desired := map[string]any{"schemas": []string{scimUserSchema}, "externalId": "stable", "active": false}
	desired["active"] = true
	if _, err := remote.reconcile(context.Background(), "Users", "", desired); err == nil {
		t.Fatal("ignored failed create")
	}
	desired["active"] = false
	id, err := remote.reconcile(context.Background(), "Users", "", desired)
	if err != nil || id != "created" || posts != 1 || lookups != 2 {
		t.Fatalf("recovery %q %v posts %d", id, err, posts)
	}
	ops, _ := patch["Operations"].([]any)
	if len(ops) != 1 {
		t.Fatalf("no patch %#v", patch)
	}
	value := ops[0].(map[string]any)["value"].(map[string]any)
	if value["active"] != false {
		t.Fatalf("wrong patch %#v", patch)
	}
}

func TestSCIMProtocolRejectsAmbiguousLookup(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"totalResults":2,"Resources":[{"id":"a","externalId":"same"},{"id":"b","externalId":"same"}]}`)
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, http: s.Client()}
	if _, err := remote.lookup(context.Background(), "Users", "same"); err == nil {
		t.Fatal("adopted ambiguous identity")
	}
}

func TestSCIMProtocolNoRedirectAndSanitizedErrors(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer s.Close()
	remote := scimRemote{base: s.URL, secret: "secret", http: s.Client()}
	err := remote.request(context.Background(), "GET", "Users", url.Values{}, nil, nil)
	if err == nil || leaked || strings.Contains(err.Error(), "secret") {
		t.Fatalf("redirect/error %v leaked=%v", err, leaked)
	}
}

func TestSCIMProtocolDeactivationDoesNotRecreateMissingUser(t *testing.T) {
	posts := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts++
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":"unwanted"}`)
			return
		}
		if r.URL.Path == "/Users" {
			fmt.Fprint(w, `{"totalResults":0,"Resources":[]}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, http: s.Client()}
	id, err := remote.reconcile(context.Background(), "Users", "removed", map[string]any{"schemas": []string{scimUserSchema}, "externalId": "managed", "active": false})
	if err != nil || id != "" || posts != 0 {
		t.Fatalf("recreated missing inactive user: id %q posts %d error %v", id, posts, err)
	}
}
func TestSCIMProtocolOpaqueResourceID(t *testing.T) {
	var escaped string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped = r.URL.EscapedPath()
		fmt.Fprint(w, `{"id":"a/b?c","externalId":"managed","active":true}`)
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL + "/base", http: s.Client()}
	_, err := remote.reconcile(context.Background(), "Users", "a/b?c", map[string]any{"schemas": []string{scimUserSchema}, "externalId": "managed", "active": true})
	if err != nil || escaped != "/base/Users/a%2Fb%3Fc" {
		t.Fatalf("escaped ID %q error %v", escaped, err)
	}
}

func TestSCIMProtocolRejectsMalformedLists(t *testing.T) {
	for _, body := range []string{"", `{}`, `{"Resources":[]}`, `{"totalResults":1,"Resources":[]}`, `{"totalResults":0,"Resources":[{"id":"x","externalId":"same"}]}`} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer s.Close()
			remote := scimRemote{base: s.URL, http: s.Client()}
			if _, err := remote.lookup(context.Background(), "Users", "same"); err == nil {
				t.Fatal("malformed list accepted as authoritative")
			}
		})
	}
}
func TestSCIMProtocolPUTPreservesNumbersAndLatestAttributes(t *testing.T) {
	gets := 0
	var raw string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			gets++
			if gets == 1 {
				fmt.Fprint(w, `{"externalId":"stable","userName":"old","removed":"old value","urn:custom":{"large":9007199254740993}}`)
			} else {
				fmt.Fprint(w, `{"externalId":"stable","userName":"old","urn:custom":{"large":9007199254740993}}`)
			}
			return
		}
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		w.WriteHeader(204)
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, http: s.Client(), usePUT: true}
	_, err := remote.reconcile(context.Background(), "Users", "one", map[string]any{"schemas": []string{scimUserSchema}, "externalId": "stable", "userName": "new"})
	if err != nil || !strings.Contains(raw, "9007199254740993") || strings.Contains(raw, "removed") {
		t.Fatalf("PUT corrupted attributes: %s error %v", raw, err)
	}
}
func TestSCIMProtocolIgnoresMemberDisplayMetadataAndOrder(t *testing.T) {
	mutations := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			mutations++
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, `{"externalId":"stable","displayName":"Team","members":[{"value":"two","display":"Bob","$ref":"/Users/two"},{"value":"one","display":"Alice"}]}`)
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, http: s.Client()}
	_, err := remote.reconcile(context.Background(), "Groups", "g", map[string]any{"schemas": []string{scimGroupSchema}, "externalId": "stable", "displayName": "Team", "members": []any{map[string]any{"value": "one"}, map[string]any{"value": "two"}}})
	if err != nil || mutations != 0 {
		t.Fatalf("unchanged group mutated %d times error %v", mutations, err)
	}
}

func TestSCIMProtocolAcceptsEmptyStandardList(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0}`)
	}))
	defer s.Close()
	remote := scimRemote{base: s.URL, http: s.Client()}
	id, err := remote.lookup(context.Background(), "Users", "absent")
	if err != nil || id != "" {
		t.Fatalf("empty list %q %v", id, err)
	}
}
