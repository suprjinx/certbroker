package authz

import "strings"

// RoleSelector maps a resolved identity to an OpenBao PKI role name. An empty
// return means "no role" and the pipeline denies the request.
type RoleSelector interface {
	Role(id Identity) string
}

// Rule maps a "key:pattern" selector (cn, ou, o, san, label, serial, "*") to a
// role. SECURITY: cn/san read the CSR at bootstrap — see threat-model.md T5.
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
