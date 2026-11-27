package app

import (
	"net/http/httptest"
	"testing"
)

func TestRequestIP(t *testing.T) {
	for _, tt := range []struct {
		name, peer string
		trusted    []string
		forwarded  []string
		real, want string
	}{
		{name: "direct", peer: "198.51.100.9:1234", want: "198.51.100.9"},
		{name: "untrusted headers", peer: "198.51.100.9:1234", forwarded: []string{"203.0.113.7"}, real: "203.0.113.8", want: "198.51.100.9"},
		{name: "trusted chain", peer: "127.0.0.1:1234", trusted: []string{"127.0.0.1", "10.0.0.0/8"}, forwarded: []string{"203.0.113.7, 10.0.0.2"}, want: "203.0.113.7"},
		{name: "repeated headers preserve trust boundary", peer: "127.0.0.1:1234", trusted: []string{"127.0.0.1"}, forwarded: []string{"203.0.113.99", "198.51.100.9"}, want: "198.51.100.9"},
		{name: "real IP fallback", peer: "127.0.0.1:1234", trusted: []string{"127.0.0.1"}, real: "203.0.113.7", want: "203.0.113.7"},
		{name: "forwarded takes precedence", peer: "127.0.0.1:1234", trusted: []string{"127.0.0.1"}, forwarded: []string{"198.51.100.9"}, real: "203.0.113.7", want: "198.51.100.9"},
		{name: "invalid forwarded does not use fallback", peer: "127.0.0.1:1234", trusted: []string{"127.0.0.1"}, forwarded: []string{"invalid"}, real: "203.0.113.7", want: "127.0.0.1"},
		{name: "invalid real IP", peer: "127.0.0.1:1234", trusted: []string{"127.0.0.1"}, real: "invalid", want: "127.0.0.1"},
		{name: "mapped peer", peer: "[::ffff:127.0.0.1]:1234", trusted: []string{"127.0.0.1"}, forwarded: []string{"2001:db8::7"}, want: "2001:db8::7"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := &App{Config: Config{TrustedProxies: tt.trusted}}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			for _, v := range tt.forwarded {
				r.Header.Add("X-Forwarded-For", v)
			}
			if tt.real != "" {
				r.Header.Set("X-Real-IP", tt.real)
			}
			if got := a.requestIP(r); got != tt.want {
				t.Fatalf("IP = %q, want %q", got, tt.want)
			}
		})
	}
}
