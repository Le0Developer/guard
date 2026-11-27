package app

import (
	"regexp"
	"strings"
	"unicode"
)

func normalizeSCIMGroupPatterns(raw string) (string, error) {
	if len(raw) > 16384 {
		return "", adminInvalid("Group whitelist must be at most 16384 bytes.")
	}
	patterns := []string{}
	seen := map[string]bool{}
	count := 0
	for _, line := range strings.Split(raw, "\n") {
		// Accept CRLF and incidental outer spacing, but no embedded controls.
		pattern := strings.TrimSpace(line)
		if pattern == "" {
			continue
		}
		count++
		if count > 100 || len(pattern) > 200 || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
			return "", adminInvalid("Use at most 100 group patterns, each at most 200 bytes without control characters.")
		}
		if !seen[pattern] {
			patterns = append(patterns, pattern)
			seen[pattern] = true
		}
	}
	return strings.Join(patterns, "\n"), nil
}

func scimGroupFilter(raw string) (func(string) bool, error) {
	normalized, err := normalizeSCIMGroupPatterns(raw)
	if err != nil {
		return nil, err
	}
	patterns := []*regexp.Regexp{}
	if normalized != "" {
		for _, line := range strings.Split(normalized, "\n") {
			// Only '*' is special. Quote every other character, including regex syntax.
			pattern, err := regexp.Compile("(?s)^" + strings.ReplaceAll(regexp.QuoteMeta(line), `\*`, ".*") + "$")
			if err != nil {
				return nil, err
			}
			patterns = append(patterns, pattern)
		}
	}
	return func(name string) bool {
		for _, pattern := range patterns {
			if pattern.MatchString(name) {
				return true
			}
		}
		return false
	}, nil
}
