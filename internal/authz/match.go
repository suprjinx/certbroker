package authz

import "strings"

// globMatch reports whether value matches pattern. Supported forms:
//
//	"*"              matches anything
//	"*.example.com"  suffix wildcard: matches sub.example.com (one or more labels)
//	"exact"          exact, case-insensitive match
//
// Matching is case-insensitive, which suits DNS names and X.509 subject fields.
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
