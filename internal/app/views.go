package app

import "strings"

func adminSection(path string) string {
	if path != "/admin" && !strings.HasPrefix(path, "/admin/") {
		return ""
	}
	section := strings.Split(strings.TrimPrefix(path, "/admin"), "/")
	if len(section) < 2 || section[1] == "" {
		return "overview"
	}
	return section[1]
}
