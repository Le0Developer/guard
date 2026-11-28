package app

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
)

// Audit projections are deliberately allowlisted. Never marshal database models:
// they contain passwords, tokens, private keys and other credentials.
type adminAuditState struct {
	Type          string
	ID            any
	Name          string
	Fields        map[string]any
	credentials   map[string]string
	loginRevision int64
}

type adminAuditChange struct {
	before     *adminAuditState
	target     any
	operations []string
}

// Capture only after the mutation handler has acquired its existing locks.
func (c *adminAuditChange) capture(ctx context.Context, q *db.Queries, target any) error {
	state, err := adminAuditSnapshot(ctx, q, target)
	if err != nil {
		return err
	}
	c.before, c.target = state, target
	return nil
}

func adminAuditSnapshot(ctx context.Context, q *db.Queries, target any) (*adminAuditState, error) {
	s := &adminAuditState{ID: target, Fields: map[string]any{}, credentials: map[string]string{}}
	f := s.Fields
	switch id := target.(type) {
	case ids.UserID:
		u, err := q.GetUser(ctx, id)
		if err != nil {
			return nil, err
		}
		s.Type, s.Name = "user", u.Username
		f["username"], f["email"], f["role"] = u.Username, u.Email, u.Role
		f["disabled"], f["force_password_reset"], f["deleted"] = u.Disabled, u.ForcePasswordReset, u.DeletedAt != nil
		s.credentials["password_changed"] = u.Password
		s.loginRevision = u.MfaRevision
		sessions, err := q.SessionsByUserId(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range sessions {
			f[fmt.Sprintf("sessions.%d", v.ID)] = map[string]any{"id": v.ID}
		}
		memberships, err := q.GroupMembersByUserId(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range memberships {
			g, err := q.GetGroup(ctx, v.GroupID)
			if err != nil {
				return nil, err
			}
			f[fmt.Sprintf("groups.%d", g.ID)] = map[string]any{"group_id": g.ID, "group_name": g.Name}
		}
	case ids.GroupID:
		g, err := q.GetGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		s.Type, s.Name = "group", g.Name
		f["name"], f["deleted"] = g.Name, g.DeletedAt != nil
		members, err := q.GroupMembersByGroupId(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range members {
			u, err := q.GetUser(ctx, v.UserID)
			if err != nil {
				return nil, err
			}
			f[fmt.Sprintf("members.%d", u.ID)] = map[string]any{"user_id": u.ID, "username": u.Username}
		}
		rules, err := q.AdminGroupAccessRules(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range rules {
			f[fmt.Sprintf("client_access_rules.%d", v.ClientID)] = map[string]any{"client_id": v.ClientID, "client_name": v.ClientName, "priority": v.Priority, "access_control": v.AccessControl}
		}

	case ids.ClientID:
		c, err := q.GetClient(ctx, id)
		if err != nil {
			return nil, err
		}
		s.Type, s.Name = "client", c.Name
		f["name"], f["client_type"], f["client_id"], f["slug"] = c.Name, c.ClientType, c.ClientID, c.Slug
		f["session_lifetime_s"], f["require_pkce"], f["disabled"] = c.SessionLifetimeS, c.RequirePkce, c.Disabled
		f["detailed_logging"], f["allow_event_reports"], f["deleted"] = c.DetailedLogging, c.AllowEventReports, c.DeletedAt != nil
		f["backchannel_logout_uri"], f["backchannel_logout_session_required"] = c.BackchannelLogoutUri, c.BackchannelLogoutSessionRequired
		s.credentials["client_secret_changed"] = c.ClientSecret
		rules, err := q.ClientAccessRulesByClientId(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range rules {
			g, err := q.GetGroup(ctx, v.GroupID)
			if err != nil {
				return nil, err
			}
			f[fmt.Sprintf("access_rules.%d", g.ID)] = map[string]any{"group_id": g.ID, "group_name": g.Name, "priority": v.Priority, "access_control": v.AccessControl}
		}
		redirects, err := q.ClientRedirectsByClientId(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range redirects {
			f[fmt.Sprintf("redirects.%d", v.ID)] = v.RedirectUri
		}
		if c.ClientType == "Saml" {
			cfg, err := q.GetSAMLConfig(ctx, id)
			if err != nil && !notFound(err) {
				return nil, err
			}
			if err == nil {
				f["saml"] = map[string]any{"entity_id": cfg.EntityID, "name_id_format": cfg.NameIDFormat, "require_signature": cfg.RequireSignature, "launch_url": cfg.LaunchUrl}
			}
			acs, err := q.SAMLACS(ctx, id)
			if err != nil {
				return nil, err
			}
			for _, v := range acs {
				f[fmt.Sprintf("saml_acs.%d", v.EndpointIndex)] = map[string]any{"url": v.Url, "is_default": v.IsDefault}
			}
			certs, err := q.SAMLSPCertificates(ctx, id)
			if err != nil {
				return nil, err
			}
			for _, v := range certs {
				fp := samlFingerprint(v.Certificate)
				f["saml_sp_certificates."+fp] = fp
			}
			keys, err := q.SAMLKeys(ctx, id)
			if err != nil {
				return nil, err
			}
			for _, v := range keys {
				f[fmt.Sprintf("saml_signing_keys.%d", v.ID)] = samlFingerprint(v.Certificate)
			}
		}
	case ids.UpstreamProviderID:
		p, err := q.GetUpstreamProvider(ctx, id)
		if err != nil {
			return nil, err
		}
		s.Type, s.Name = "provider", p.Name
		f["name"], f["slug"], f["issuer"] = p.Name, p.Slug, p.Issuer
		f["authorize_url"], f["token_url"], f["userinfo_url"], f["jwks_url"] = p.AuthorizeUrl, p.TokenUrl, p.UserinfoUrl, p.JwksUrl
		f["client_id"], f["scopes"], f["pkce"], f["signing_alg"] = p.ClientID, p.Scopes, p.Pkce, p.SigningAlg
		f["enabled"], f["backchannel_logout_enabled"], f["deleted"] = p.Enabled, p.BackchannelLogoutEnabled, p.DeletedAt != nil
		f["configuration_mode"], f["discovery_url"] = p.ConfigurationMode, p.DiscoveryUrl
		f["subject_field"], f["email_field"], f["email_verified_field"], f["client_auth_method"] = p.SubjectField, p.EmailField, p.EmailVerifiedField, p.ClientAuthMethod
		s.credentials["client_secret_changed"] = p.ClientSecret
		s.loginRevision = p.Revision
		sessions, err := q.AdminProviderSessions(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, sid := range sessions {
			f[fmt.Sprintf("sessions.%d", sid)] = map[string]any{"id": sid}
		}
	default:
		return nil, fmt.Errorf("unsupported admin audit target %T", target)
	}
	return s, nil
}

func adminAuditDiff(before, after *adminAuditState) (map[string]any, []string) {
	changes := map[string]any{}
	old := map[string]any{}
	secrets := map[string]string{}
	if before != nil {
		old = before.Fields
		secrets = before.credentials
	}
	for k, v := range after.Fields {
		if prior, ok := old[k]; !ok || !reflect.DeepEqual(adminAuditComparable(k, prior), adminAuditComparable(k, v)) {
			changes[k] = map[string]any{"before": old[k], "after": v}
		}
	}
	for k, v := range old {
		if _, ok := after.Fields[k]; !ok {
			changes[k] = map[string]any{"before": v, "after": nil}
		}
	}
	operations := []string{}
	for k, v := range after.credentials {
		if secrets[k] != v {
			operations = append(operations, k)
		}
	}
	if before != nil && before.loginRevision != after.loginRevision {
		operations = append(operations, "pending_logins_invalidated")
	}
	sort.Strings(operations)
	return changes, operations
}

// Related names provide historical context, but a concurrent rename alone is
// not a membership or access-rule change made by this administrator.
func adminAuditComparable(field string, value any) any {
	prefix, _, _ := strings.Cut(field, ".")
	label := ""
	switch prefix {
	case "members":
		label = "username"
	case "groups", "access_rules":
		label = "group_name"
	case "client_access_rules":
		label = "client_name"
	default:
		return value
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return value
	}
	comparable := make(map[string]any, len(fields))
	for k, v := range fields {
		if k != label {
			comparable[k] = v
		}
	}
	return comparable
}

func adminAuditDetails(before, after *adminAuditState) map[string]any {
	changes, operations := adminAuditDiff(before, after)
	outcome := "updated"
	switch {
	case before == nil:
		outcome = "created"
	case before.Fields["deleted"] != true && after.Fields["deleted"] == true:
		outcome = "deleted"
	case len(changes) == 0 && len(operations) == 0:
		outcome = "unchanged"
	}
	return map[string]any{"target_id": after.ID, "target": map[string]any{"type": after.Type, "id": after.ID, "name": after.Name}, "outcome": outcome, "changes": changes, "operations": operations}
}

func adminAuditData(r *http.Request, before, after *adminAuditState) map[string]any {
	data := adminAuditDetails(before, after)
	data["action"], data["status"] = r.Pattern, 303
	data["summary"] = adminAuditSummary(r, after.Type, data["outcome"].(string))
	return data
}

func adminAuditSCIMState(client db.Client, cfg db.ScimConfig) *adminAuditState {
	return &adminAuditState{Type: "client", ID: client.ID, Name: client.Name, Fields: map[string]any{"endpoint": cfg.Endpoint, "enabled": cfg.Enabled, "group_patterns": cfg.GroupPatterns}, credentials: map[string]string{"scim_secret_changed": cfg.Secret}}
}

func adminAuditSummary(r *http.Request, kind, outcome string) string {
	if outcome == "unchanged" {
		return "No changes to " + kind
	}
	path := r.URL.Path
	switch {
	case strings.Contains(path, "/rules"):
		if strings.HasSuffix(path, "/remove") {
			return "Access rule removed"
		}
		return "Access rule saved"
	case strings.Contains(path, "/redirects"):
		if strings.HasSuffix(path, "/remove") {
			return "Redirect URI removed"
		}
		return "Redirect URI saved"
	case strings.Contains(path, "/members"):
		if strings.HasSuffix(path, "/remove") {
			return "Group member removed"
		}
		return "Group member added"
	case strings.HasSuffix(path, "/rotate-secret"):
		return "Client secret rotated"
	case strings.HasSuffix(path, "/password"):
		return "User password changed"
	case strings.HasSuffix(path, "/role"):
		return "User role changed"
	case strings.Contains(path, "/sessions"):
		return "User sessions revoked"
	case strings.HasSuffix(path, "/saml"):
		return "SAML configuration saved"
	}
	return strings.ToUpper(kind[:1]) + kind[1:] + " " + outcome
}
