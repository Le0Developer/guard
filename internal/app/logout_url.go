package app

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// validateLogoutURI permits plain HTTP only for loopback development endpoints.
func validateLogoutURI(raw string) error {
	if raw == "" {
		return nil
	}
	invalid := func() error {
		return fmt.Errorf("Back-channel logout URI must be an absolute HTTPS URL (HTTP only on localhost or loopback), without credentials, fragments, wildcards, whitespace, backslashes or control characters; maximum 2048 bytes.")
	}
	if len(raw) > 2048 || strings.ContainsAny(raw, "*#\\") || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return invalid()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return invalid()
	}
	if strings.HasSuffix(u.Host, ":") {
		return invalid()
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return invalid()
		}
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return invalid()
}
