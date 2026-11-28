package app

import (
	"encoding/base64"
	"html/template"

	"github.com/skip2/go-qrcode"
)

func mfaQRCode(uri string) (template.URL, error) {
	png, err := qrcode.Encode(uri, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	// Only locally generated PNG data is marked safe for use in an image URL.
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}
