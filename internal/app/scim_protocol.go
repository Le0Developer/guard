package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
const scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
const scimResponseLimit = 2 << 20

// Remote response bodies and URLs never enter operator errors: they can contain
// credentials and personal data. Status and protocol categories are sufficient.
type scimError struct {
	status     int
	message    string
	retryAfter string
}

func (e *scimError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("SCIM HTTP %d: %s", e.status, e.message)
	}
	return "SCIM: " + e.message
}
func scimProblem(message string) error { return &scimError{message: message} }
func scimStatus(err error, status int) bool {
	var e *scimError
	return errors.As(err, &e) && e.status == status
}
func scimPermanent(err error) bool {
	var e *scimError
	if !errors.As(err, &e) {
		return false
	}
	return e.status == 0 || e.status >= 300 && e.status < 500 && e.status != 408 && e.status != 429
}

func validateSCIMURL(raw string) error {
	if len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t\\") {
		return scimProblem("invalid endpoint URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" {
		return scimProblem("invalid endpoint URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return scimProblem("endpoint requires HTTPS (HTTP allowed only on loopback)")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return scimProblem("endpoint contains a dot segment")
		}
	}
	if strings.Contains(u.Host, "*") {
		return scimProblem("invalid endpoint host")
	}
	return nil
}

type scimRemote struct {
	base, secret string
	http         *http.Client
	usePUT       bool
	before       func(context.Context) error
}

func scimResource(kind, id string) (string, error) {
	if kind != "Users" && kind != "Groups" {
		return "", scimProblem("invalid resource type")
	}
	if id == "" || id == "." || id == ".." || len(id) > 1024 || strings.ContainsAny(id, "\r\n") {
		return "", scimProblem("invalid resource identifier")
	}
	return kind + "/" + url.PathEscape(id), nil
}
func (s *scimRemote) request(ctx context.Context, method, resource string, query url.Values, input, output any) error {
	if err := validateSCIMURL(s.base); err != nil {
		return err
	}
	if s.before != nil {
		if err := s.before(ctx); err != nil {
			return err
		}
	}
	u, err := url.Parse(strings.TrimRight(s.base, "/") + "/" + resource)
	if err != nil {
		return scimProblem("invalid resource URL")
	}
	u.RawQuery = query.Encode()
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return scimProblem("cannot encode resource")
		}
		if len(body) > scimResponseLimit {
			return scimProblem("resource exceeds size limit")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return scimProblem("invalid request")
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	req.Header.Set("Accept", "application/scim+json")
	if input != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	client := *s.http
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &scimError{status: 503, message: "transport failure"}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, scimResponseLimit+1))
	if err != nil {
		return &scimError{status: 503, message: "incomplete response"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &scimError{status: resp.StatusCode, message: "request failed", retryAfter: resp.Header.Get("Retry-After")}
	}
	if len(b) > scimResponseLimit {
		return scimProblem("response exceeds size limit")
	}
	if output != nil && len(bytes.TrimSpace(b)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber()
		if err = decoder.Decode(output); err != nil {
			return scimProblem("invalid JSON response")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return scimProblem("invalid JSON response")
		}
	}
	return nil
}

func (s *scimRemote) discover(ctx context.Context) error {
	var config struct {
		Patch struct {
			Supported *bool `json:"supported"`
		} `json:"patch"`
	}
	// Absence of capability discovery is common; PATCH remains the default.
	err := s.request(ctx, "GET", "ServiceProviderConfig", nil, nil, &config)
	if scimStatus(err, 404) || scimStatus(err, 405) || scimStatus(err, 501) {
		return nil
	}
	if err != nil {
		return err
	}
	// An omitted patch declaration must not silently switch update semantics.
	s.usePUT = config.Patch.Supported != nil && !*config.Patch.Supported
	return nil
}

func (s *scimRemote) lookup(ctx context.Context, kind, externalID string) (string, error) {
	filterValue, _ := json.Marshal(externalID)
	found := ""
	for start, pages := 1, 0; pages < 1000; pages++ {
		var list struct {
			Total     *int             `json:"totalResults"`
			Start     *int             `json:"startIndex"`
			Count     *int             `json:"itemsPerPage"`
			Resources []map[string]any `json:"Resources"`
		}
		q := url.Values{"filter": {"externalId eq " + string(filterValue)}, "startIndex": {strconv.Itoa(start)}, "count": {"100"}}
		if err := s.request(ctx, "GET", kind, q, nil, &list); err != nil {
			return "", err
		}
		if list.Total == nil || *list.Total < 0 || *list.Total > 100000 || len(list.Resources) > *list.Total || (len(list.Resources) > 0 && start-1+len(list.Resources) > *list.Total) || (list.Start != nil && *list.Start != start) || (list.Count != nil && *list.Count != len(list.Resources)) {
			return "", scimProblem("invalid or excessive result count")
		}
		for _, r := range list.Resources {
			if r["externalId"] == externalID {
				id, _ := r["id"].(string)
				if _, err := scimResource(kind, id); err != nil {
					return "", err
				}
				if found != "" {
					return "", scimProblem("ambiguous externalId match")
				}
				found = id
			}
		}
		start += len(list.Resources)
		if start > *list.Total {
			return found, nil
		}
		if len(list.Resources) == 0 {
			return "", scimProblem("pagination made no progress")
		}
	}
	return "", scimProblem("pagination limit exceeded")
}

// reconcile manages only owned attributes; PUT preserves unrelated attributes.
// Lookup precedes every create, recovering successful POSTs whose reply was lost.
func (s *scimRemote) reconcile(ctx context.Context, kind, remoteID string, desired map[string]any) (string, error) {
	externalID, _ := desired["externalId"].(string)
	if externalID == "" {
		return "", scimProblem("missing externalId")
	}
	for tries := 0; tries < 2; tries++ {
		if remoteID == "" {
			var err error
			remoteID, err = s.lookup(ctx, kind, externalID)
			if err != nil {
				return "", err
			}
		}
		if remoteID == "" {
			if kind == "Users" && desired["active"] == false {
				return "", nil
			}
			var created map[string]any
			if err := s.request(ctx, "POST", kind, nil, desired, &created); err != nil {
				return "", err
			}
			id, _ := created["id"].(string)
			if id == "" {
				var err error
				id, err = s.lookup(ctx, kind, externalID)
				if err != nil {
					return "", err
				}
			}
			if _, err := scimResource(kind, id); err != nil {
				return "", err
			}
			return id, nil
		}
		resource, err := scimResource(kind, remoteID)
		if err != nil {
			return "", err
		}
		var current map[string]any
		err = s.request(ctx, "GET", resource, nil, nil, &current)
		if scimStatus(err, 404) {
			remoteID = ""
			continue
		}
		if err != nil {
			return "", err
		}
		// A mapped resource must still identify the same managed identity.
		if current["externalId"] != externalID {
			return "", scimProblem("remote resource ownership changed")
		}
		changed := map[string]any{}
		for k, v := range desired {
			if k == "schemas" {
				continue
			}
			if !reflect.DeepEqual(scimComparable(k, current[k]), scimComparable(k, v)) {
				changed[k] = v
			}
		}
		if len(changed) == 0 {
			return remoteID, nil
		}
		if !s.usePUT {
			patch := map[string]any{"schemas": []string{scimPatchSchema}, "Operations": []any{map[string]any{"op": "replace", "value": changed}}}
			err = s.request(ctx, "PATCH", resource, nil, patch, nil)
			if err == nil {
				return remoteID, nil
			}
			if !scimStatus(err, 405) && !scimStatus(err, 501) {
				return "", err
			}
			s.usePUT = true
		}
		// Refresh into a fresh map: omitted attributes must not be resurrected.
		current = nil
		if err = s.request(ctx, "GET", resource, nil, nil, &current); err != nil {
			return "", err
		}
		if current["externalId"] != externalID {
			return "", scimProblem("remote resource ownership changed")
		}
		for k, v := range desired {
			if k != "schemas" {
				current[k] = v
			}
		}
		schemas := []string{}
		if values, ok := current["schemas"].([]any); ok {
			for _, v := range values {
				if str, ok := v.(string); ok {
					schemas = append(schemas, str)
				}
			}
		}
		rawSchemas, _ := json.Marshal(desired["schemas"])
		var desiredSchemas []string
		_ = json.Unmarshal(rawSchemas, &desiredSchemas)
		for _, v := range desiredSchemas {
			exists := false
			for _, old := range schemas {
				if old == v {
					exists = true
				}
			}
			if !exists {
				schemas = append(schemas, v)
			}
		}
		current["schemas"] = schemas
		delete(current, "meta")
		delete(current, "id")
		delete(current, "groups") // read-only User attributes
		if err = s.request(ctx, "PUT", resource, nil, current, nil); err != nil {
			return "", err
		}
		return remoteID, nil
	}
	return "", scimProblem("resource repeatedly disappeared")
}

func (s *scimRemote) deleteGroup(ctx context.Context, id, externalID string) error {
	resource, err := scimResource("Groups", id)
	if err != nil {
		return err
	}
	var current map[string]any
	if err = s.request(ctx, "GET", resource, nil, nil, &current); scimStatus(err, 404) {
		return nil
	}
	if err != nil {
		return err
	}
	if current["externalId"] != externalID {
		return scimProblem("remote resource ownership changed")
	}
	err = s.request(ctx, "DELETE", resource, nil, nil, nil)
	if scimStatus(err, 404) {
		return nil
	}
	return err
}

// Compare only owned fields and treat multivalued attributes as sets. Servers
// may attach read-only display/$ref fields or return members in another order.
func scimComparable(attribute string, value any) any {
	b, _ := json.Marshal(value)
	var canonical any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&canonical)
	if attribute != "members" && attribute != "emails" {
		return canonical
	}
	rows, ok := canonical.([]any)
	if !ok && canonical != nil {
		return canonical
	}
	values := []string{}
	for _, row := range rows {
		item, ok := row.(map[string]any)
		if !ok {
			return canonical
		}
		str, ok := item["value"].(string)
		if !ok {
			return canonical
		}
		if attribute == "emails" {
			primary, _ := item["primary"].(bool)
			str = fmt.Sprintf("%s:%t", str, primary)
		}
		values = append(values, str)
	}
	sort.Strings(values)
	return values
}
