package app

import (
	"bytes"
	"encoding/base64"
	"html"
	"html/template"
	"image/png"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestTOTPSetupQRCode(t *testing.T) {
	const uri = "otpauth://totp/Guard:alice?secret=JBSWY3DPEHPK3PXP&issuer=Guard&algorithm=SHA1&digits=6&period=30"
	qr, err := mfaQRCode(uri)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(&App{}).page(w, httptest.NewRequest("POST", "/security/totp", nil), "Set up authenticator", totpSetupTemplate, map[string]any{
		"Base": "/security", "Secret": "JBSWY3DPEHPK3PXP", "URI": template.URL(uri), "QRCode": qr, "Ticket": "enrollment-ticket",
	})
	if w.Code != 200 {
		t.Fatalf("render: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	match := regexp.MustCompile(`<img[^>]+src="data:image/png;base64,([^" ]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("setup page does not contain an embedded QR image: %s", regexp.MustCompile(`<img[^>]+>`).FindAllString(body, -1))
	}
	raw, err := base64.StdEncoding.DecodeString(html.UnescapeString(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() < 256 || img.Bounds().Dy() != img.Bounds().Dx() {
		t.Fatalf("unexpected QR dimensions: %v", img.Bounds())
	}
	for _, want := range []string{`alt="`, "JBSWY3DPEHPK3PXP", `href="otpauth://totp/Guard:alice?`, `action="/security/totp/confirm"`, `value="enrollment-ticket"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing setup option %q", want)
		}
	}
}
