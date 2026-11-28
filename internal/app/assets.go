package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// The embedded contents are fixed for the lifetime of the binary.
var assetPaths = func() map[string]string {
	entries, err := fs.ReadDir(assets, "assets")
	if err != nil {
		panic(err)
	}
	paths := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		content, err := assets.ReadFile("assets/" + name)
		if err != nil {
			panic(err)
		}
		digest := sha256.Sum256(content)
		ext := path.Ext(name)
		paths[name] = fmt.Sprintf("/static/%s.%x%s", strings.TrimSuffix(name, ext), digest[:6], ext)
	}
	return paths
}()

func assetPath(name string) (string, error) {
	url, ok := assetPaths[name]
	if !ok {
		return "", fmt.Errorf("unknown static asset %q", name)
	}
	return url, nil
}

func registerAssets(mux *http.ServeMux) {
	for name, url := range assetPaths {
		content, err := assets.ReadFile("assets/" + name)
		if err != nil {
			panic(err)
		}
		mux.HandleFunc("GET "+url, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
		})
	}
}
