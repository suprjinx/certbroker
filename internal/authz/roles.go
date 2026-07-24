package authz

import "strings"

// RoleSelector maps a resolved identity to an OpenBao PKI role name. An empty
// return means "no role" and the pipeline denies the request.
type RoleSelector interface {
	Role(id Identity) string
}

// Rule maps a selector to a role. Selectors have the form "key:pattern", where
// key is one of:
//
//	cn     — authenticated cert CN (falls back to requested CN if unauthenticated)
//	ou     — any authenticated cert OU
//	o      — any authenticated cert O
//	san    — any requested CSR dNSName
//	label  — the EST URI label
//	serial — authenticated cert serial (lowercase hex)
//	*      — matches any identity
//
// pattern supports the wildcard forms of globMatch ("*", "*.suffix", exact).
type Rule struct {
	Match string
	Role  string
}

// RuleSelector evaluates rules in order, first match wins, then falls back to
// Default.
type RuleSelector struct {
	Rules   []Rule
	Default string
}

// NewRuleSelector builds a RuleSelector.
func NewRuleSelector(rules []Rule, def string) *RuleSelector {
	return &RuleSelector{Rules: rules, Default: def}
}

// Role implements RoleSelector.
func (s *RuleSelector) Role(id Identity) string {
	for _, r := range s.Rules {
		if matchSelector(r.Match, id) {
			return r.Role
		}
	}
	return s.Default
}

// matchSelector reports whether a "key:pattern" selector matches the identity.
// A bare "*" matches anything.
func matchSelector(selector string, id Identity) bool {
	selector = strings.TrimSpace(selector)
	if selector == "*" {
		return true
	}
	key, pattern, ok := strings.Cut(selector, ":")
	if !ok {
		return false
	}
	key = strings.ToLower(strings.TrimSpace(key))
	pattern = strings.TrimSpace(pattern)

	switch key {
	case "cn":
		cn := id.CommonName
		if cn == "" {
			cn = id.RequestedCN
		}
		return globMatch(pattern, cn)
	case "ou":
		return anyGlobMatch(pattern, id.OrgUnits)
	case "o":
		return anyGlobMatch(pattern, id.Orgs)
	case "san":
		return anyGlobMatch(pattern, id.RequestedDNS)
	case "label":
		return globMatch(pattern, id.Label)
	case "serial":
		return globMatch(pattern, id.Serial)
	default:
		return false
	}
}
