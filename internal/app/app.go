package app

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

const SessionLifetime = 18 * time.Hour

type Config struct {
	BrandName, BrandIconFile                                                 string
	Domain, DatabaseURL, ListenAddr, ForwardAuthListenAddr, MFAEncryptionKey string
	PasswordDisabled                                                         bool
	TrustedProxies                                                           []string
	ExportURL, ExportToken                                                   string
	ReportLimit                                                              int32
}
type App struct {
	upstreamKeys  upstreamKeyCache
	Pool          *pgxpool.Pool
	Q             *db.Queries
	Config        Config
	HTTP          *http.Client
	secret        string
	dummyPassword string
	rateMu        sync.Mutex
	rates         map[string]rateBucket
	workers       chan struct{}
}
type rateBucket struct {
	Tokens  float64
	Updated time.Time
}
type identity struct {
	User    db.User
	Session db.Session
}
type identityKey struct{}
type csrfKey struct{}

func New(pool *pgxpool.Pool, c Config) (*App, error) {
	a := &App{Pool: pool, Q: db.New(pool), Config: c, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, rates: map[string]rateBucket{}, workers: make(chan struct{}, 4)}
	return a, a.initialize()
}
func (a *App) user(r *http.Request) (*identity, bool) {
	v, ok := r.Context().Value(identityKey{}).(*identity)
	return v, ok && v != nil
}
func (a *App) requireUser(w http.ResponseWriter, r *http.Request) (*identity, bool) {
	v, ok := a.user(r)
	if !ok {
		http.Redirect(w, r, "/login?r="+queryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	}
	return v, ok
}
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (*identity, bool) {
	v, ok := a.requireUser(w, r)
	if !ok {
		return nil, false
	}
	if v.User.Role != "Admin" {
		a.fail(w, r, 403, "You need an administrator account to view this page.")
		return nil, false
	}
	return v, true
}
func (a *App) fail(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}
func (a *App) serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "path", r.URL.Path, "error", err)
	a.fail(w, r, 503, "Unable to complete this request.")
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (a *App) page(w http.ResponseWriter, r *http.Request, title, body string, data any) {
	t, err := template.New("page").Parse(layout + adminNavigation + adminCSRF + `{{define "content"}}` + body + `{{end}}`)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	var current *db.User
	if v, ok := a.user(r); ok {
		current = &v.User
	}
	view := map[string]any{"BrandName": a.Config.brandName(), "BrandIcon": a.Config.BrandIconFile != "", "Title": title, "CSRF": csrf(r), "User": current, "Data": data, "AdminSection": adminSection(r.URL.Path)}
	// Render before committing headers so template failures cannot emit a partial page.
	var b byteBuffer
	if err = t.Execute(&b, view); err != nil {
		a.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

type byteBuffer []byte

func (b *byteBuffer) Write(p []byte) (int, error) { *b = append(*b, p...); return len(p), nil }

func (a *App) audit(ctx context.Context, q *db.Queries, user ids.UserID, event string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = q.CreateAuditLog(ctx, db.CreateAuditLogParams{UserID: user, Event: event, Data: b})
	return err
}
func (a *App) permitted(ctx context.Context, q *db.Queries, client ids.ClientID, user ids.UserID) (bool, error) {
	rules, err := q.ClientAccessRulesByClientId(ctx, client)
	if err != nil {
		return false, err
	}
	if len(rules) == 0 {
		return true, nil
	}
	members, err := q.GroupMembersByUserId(ctx, user)
	if err != nil {
		return false, err
	}
	var chosen *db.ClientAccessRule
	for _, rule := range rules {
		for _, member := range members {
			if member.GroupID != rule.GroupID {
				continue
			}
			g, err := q.GetGroup(ctx, rule.GroupID)
			if err != nil {
				return false, err
			}
			if g.DeletedAt != nil {
				continue
			}
			if chosen == nil || rule.Priority < chosen.Priority || (rule.Priority == chosen.Priority && rule.AccessControl == "Deny") {
				copy := rule
				chosen = &copy
			}
		}
	}
	return chosen != nil && chosen.AccessControl == "Allow", nil
}
func (a *App) sessionByID(ctx context.Context, q *db.Queries, id ids.SessionID) (*identity, error) {
	s, err := q.GetSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !s.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	u, err := q.GetUser(ctx, s.UserID)
	if err != nil {
		return nil, err
	}
	if u.Disabled || u.DeletedAt != nil {
		return nil, nil
	}
	return &identity{u, s}, nil
}
func transaction(ctx context.Context, pool *pgxpool.Pool, fn func(*db.Queries) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = fn(db.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func ptr[T any](v T) *T       { return &v }
func notFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
