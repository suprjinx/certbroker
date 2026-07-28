package authz

import "strings"

// globMatch matches value against "*" (anything), "*.suffix" (one or more
// leading labels), or an exact string. Case-insensitive throughout.
func globMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*."):
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(value, suffix) && len(value) > len(suffix)
	default:
		return pattern == value
	}
}

// anyGlobMatch reports whether pattern matches any of the values.
func anyGlobMatch(pattern string, values []string) bool {
	for _, v := range values {
		if globMatch(pattern, v) {
			return true
		}
	}
	return false
}

// allAllowed reports whether every name is permitted by at least one pattern.
// An empty names list is trivially allowed.
func allAllowed(names, patterns []string) bool {
	for _, n := range names {
		ok := false
		for _, p := range patterns {
			if globMatch(p, n) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
