package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"github.com/le0developer/guard/internal/security"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func queryEscape(s string) string { return url.QueryEscape(s) }
func csrf(r *http.Request) string { s, _ := r.Context().Value(csrfKey{}).(string); return s }
func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
func (a *App) setCookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.Config.Domain, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func (a *App) requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap()
	trusted := func(ip netip.Addr) bool {
		for _, s := range a.Config.TrustedProxies {
			if p, e := netip.ParsePrefix(s); e == nil && p.Contains(ip) {
				return true
			}
			if v, e := netip.ParseAddr(s); e == nil && v.Unmap() == ip {
				return true
			}
		}
		return false
	}
	if trusted(ip) {
		forwarded := r.Header.Values("X-Forwarded-For")
		if len(forwarded) == 0 {
			// Only a trusted peer may supply the single-address fallback.
			if values := r.Header.Values("X-Real-IP"); len(values) == 1 {
				if v, err := netip.ParseAddr(strings.TrimSpace(values[0])); err == nil {
					return v.Unmap().String()
				}
			}
			return ip.String()
		}
		// Repeated fields form one ordered chain, just like comma-separated values.
		chain := strings.Split(strings.Join(forwarded, ","), ",")
		for i := len(chain) - 1; i >= 0; i-- {
			v, e := netip.ParseAddr(strings.TrimSpace(chain[i]))
			if e != nil {
				return ip.String()
			}
			ip = v.Unmap()
			if !trusted(ip) {
				break
			}
		}
	}
	return ip.String()
}
func (a *App) allowLogin(ip string) int {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	now := time.Now()
	if a.rates == nil {
		a.rates = map[string]rateBucket{}
	}
	for key, b := range a.rates {
		if now.Sub(b.Updated) > 5*time.Minute {
			delete(a.rates, key)
		}
	}
	b, ok := a.rates[ip]
	if !ok {
		if len(a.rates) >= 65536 {
			return 60
		}
		b = rateBucket{Tokens: 5, Updated: now}
	}
	b.Tokens = math.Min(5, b.Tokens+now.Sub(b.Updated).Minutes())
	b.Updated = now
	wait := 0
	if b.Tokens < 1 {
		wait = int(math.Ceil((1 - b.Tokens) * 60))
	} else {
		b.Tokens--
	}
	a.rates[ip] = b
	return wait
}
func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		session := cookieValue(r, "session")
		mac := hmac.New(sha256.New, []byte(a.secret))
		mac.Write([]byte(a.requestIP(r) + "\x00" + session))
		token := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		r = r.WithContext(context.WithValue(r.Context(), csrfKey{}, token))
		if cookieValue(r, "csrf_token") != token {
			a.setCookie(w, "csrf_token", token, 0)
		}
		if r.Method == "POST" && !strings.HasPrefix(r.URL.Path, "/oauth2/") && !isUpstreamLogoutPath(r.URL.Path) {
			if err := r.ParseForm(); err != nil || len(r.PostForm["csrf_token"]) != 1 || !security.Equal(r.PostForm.Get("csrf_token"), token) {
				a.fail(w, r, 403, "Invalid CSRF token. Reload the page and try again.")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != a.Config.Domain {
				a.fail(w, r, 403, "Invalid request origin.")
				return
			}
		}
		if session != "" && a.Q != nil {
			s, err := a.Q.SessionByTokenHash(r.Context(), security.Hash(session))
			if err == nil {
				v, err := a.browserSessionByID(r.Context(), a.Q, s.ID, true)
				if err != nil {
					a.serverError(w, r, err)
					return
				}
				if v != nil {
					if v.User.ForcePasswordReset && !passwordResetAllowedPath(r.URL.Path) {
						http.Redirect(w, r, passwordResetURL(r.URL.RequestURI()), http.StatusSeeOther)
						return
					}
					r = r.WithContext(context.WithValue(r.Context(), identityKey{}, v))
				}
			} else if !notFound(err) {
				a.serverError(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /branding/icon", func(w http.ResponseWriter, r *http.Request) {
		if a.Config.BrandIconFile == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, a.Config.BrandIconFile)
	})
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /userinfo-simulator", a.userinfoSimulator)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("POST /login", a.passwordLogin)
	mux.HandleFunc("GET /login/{method}", a.login)
	mux.HandleFunc("POST /login/{method}", a.passwordLogin)
	mux.HandleFunc("GET /login/{method}/callback", a.upstreamCallback)
	mux.HandleFunc("POST /login/{method}/backchannel-logout", a.upstreamBackchannelLogout)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /password-reset", a.passwordReset)
	mux.HandleFunc("POST /password-reset", a.passwordReset)
	sub, _ := fs.Sub(assets, "assets")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))
	mux.HandleFunc("GET /saml/{slug}/metadata", a.samlMetadata)
	mux.HandleFunc("GET /saml/{slug}/sso", a.samlSSO)
	mux.HandleFunc("GET /saml/{slug}/continue", a.samlContinue)
	mux.HandleFunc("POST /saml/{slug}/issue", a.samlIssue)
	a.registerOAuth(mux)
	a.registerIntrospection(mux)
	a.registerMFA(mux)
	a.registerAdmin(mux)
	a.registerUpstreamAdmin(mux)
	mux.HandleFunc("POST /oauth2/event", a.eventReport)
	return a.middleware(mux)
}
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	v, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	apps, err := a.launcherApps(r, v.User.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.page(w, r, "My account", homeTemplate, map[string]any{"Account": v.User, "Apps": apps})
}
