package lab

import (
	"strings"

	"github.com/activecm/rita/v5/util"
)

func MatchAllowlist(rules []AllowlistRule, domain string) AllowlistMatch {
	domain = NormalizeDomain(domain)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		pattern := NormalizeAllowlistPattern(rule.Pattern)
		if util.ContainsDomain([]string{pattern}, domain) {
			return AllowlistMatch{Rule: rule, Matched: true}
		}
	}
	return AllowlistMatch{}
}

func NormalizeAllowlistPattern(pattern string) string {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if strings.HasPrefix(pattern, "*.") {
		return "*." + NormalizeDomain(strings.TrimPrefix(pattern, "*."))
	}
	return NormalizeDomain(pattern)
}
