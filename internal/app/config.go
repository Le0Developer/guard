package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/security"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func LoadConfig() (Config, error) { return configFromEnv(os.Getenv) }
func configFromEnv(get func(string) string) (Config, error) {
	c := Config{Domain: strings.TrimRight(get("DOMAIN"), "/"), DatabaseURL: get("DATABASE_URL"), ListenAddr: get("LISTEN_ADDR"), ForwardAuthListenAddr: get("FORWARDAUTH_LISTEN_ADDR"), MFAEncryptionKey: get("MFA_ENCRYPTION_KEY"), ExportURL: get("ACCESS_LOG_EXPORT_URL"), ExportToken: get("ACCESS_LOG_EXPORT_TOKEN"), ReportLimit: 600}
	c.BrandName = strings.TrimSpace(get("BRAND_NAME"))
	c.BrandIconFile = get("BRAND_ICON_FILE")
	if c.BrandIconFile != "" {
		switch strings.ToLower(filepath.Ext(c.BrandIconFile)) {
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp":
		default:
			return c, errors.New("BRAND_ICON_FILE must be a PNG, JPEG, GIF, SVG, ICO, or WebP file")
		}
		f, err := os.Open(c.BrandIconFile)
		if err != nil {
			return c, fmt.Errorf("BRAND_ICON_FILE: %w", err)
		}
		info, err := f.Stat()
		f.Close()
		if err != nil {
			return c, fmt.Errorf("BRAND_ICON_FILE: %w", err)
		}
		if !info.Mode().IsRegular() {
			return c, errors.New("BRAND_ICON_FILE must be a regular file")
		}
	}
	origin, err := security.Origin(c.Domain)
	if err != nil {
		return c, fmt.Errorf("DOMAIN: %w", err)
	}
	u, _ := url.Parse(origin)
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return c, errors.New("DOMAIN requires HTTPS except on loopback")
	}
	c.Domain = origin
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL is required (PostgreSQL)")
	}
	dbURL, err := url.Parse(c.DatabaseURL)
	if err != nil || (dbURL.Scheme != "postgres" && dbURL.Scheme != "postgresql") {
		return c, errors.New("DATABASE_URL must be a PostgreSQL URL")
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:4444"
	}
	if c.ForwardAuthListenAddr == "" {
		c.ForwardAuthListenAddr = "127.0.0.1:4445"
	}
	if s := get("PASSWORD_DISABLED"); s != "" {
		if s != "true" && s != "false" {
			return c, errors.New("PASSWORD_DISABLED must be true or false")
		}
		c.PasswordDisabled = s == "true"
	}
	if c.MFAEncryptionKey != "" {
		b, err := base64.RawURLEncoding.DecodeString(c.MFAEncryptionKey)
		if err != nil || len(b) != 32 {
			return c, errors.New("MFA_ENCRYPTION_KEY must be 32 bytes encoded as unpadded base64url")
		}
	}
	if c.ExportURL != "" {
		u, err := security.URL(c.ExportURL)
		if err != nil || u.Scheme != "https" {
			return c, errors.New("ACCESS_LOG_EXPORT_URL must be HTTPS")
		}
	}
	if s := get("AUDIT_EVENT_REPORTS_PER_MINUTE"); s != "" {
		n, err := strconv.ParseInt(s, 10, 32)
		if err != nil || n < 1 {
			return c, errors.New("invalid report limit")
		}
		c.ReportLimit = int32(n)
	}
	for _, s := range strings.Split(get("AUDIT_TRUSTED_PROXIES"), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err = netip.ParseAddr(s); err != nil {
				return c, fmt.Errorf("invalid trusted proxy %q", s)
			}
		}
		c.TrustedProxies = append(c.TrustedProxies, s)
	}
	return c, nil
}

func (c Config) brandName() string {
	if strings.TrimSpace(c.BrandName) == "" {
		return "Guard"
	}
	return c.BrandName
}
