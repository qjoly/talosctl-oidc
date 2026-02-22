// Package rbac provides role-based access control (RBAC) mapping
// based on OIDC claims.
//
// The RBAC mapper evaluates rules in order and assigns roles based on
// matching claim values. If no rules match, default roles can be applied.
package rbac

import (
	"fmt"
	"os"
	"strings"

	"github.com/qjoly/talosctl-oidc/pkg/config"
)

func debug(format string, v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		fmt.Printf("[DEBUG] [RBAC] "+format+"\n", v...)
	}
}

// Mapper handles mapping OIDC claims to Talos roles.
type Mapper struct {
	rules        []config.RBACRule
	defaultRoles []string
}

// NewMapper creates a new RBAC mapper with the given rules and default roles.
// If no rules are provided, all users will receive the default roles.
func NewMapper(rules []config.RBACRule, defaultRoles []string) *Mapper {
	return &Mapper{
		rules:        rules,
		defaultRoles: defaultRoles,
	}
}

// MapRoles evaluates the OIDC claims against the configured RBAC rules
// and returns the appropriate Talos roles for the user.
//
// Claims can contain various data types. This function handles:
//   - String values: direct comparison
//   - Array values: checks if the expected value is in the array
//
// Rules are evaluated in order, and all matching rules' roles are combined.
// If no rules match, the default roles are returned.
func (m *Mapper) MapRoles(claims map[string]interface{}) []string {
	if len(m.rules) == 0 {
		debug("No RBAC rules configured, using default roles: %v", m.defaultRoles)
		return m.defaultRoles
	}

	debug("Evaluating %d RBAC rules against claims", len(m.rules))

	roleSet := make(map[string]struct{})
	matched := false

	for i, rule := range m.rules {
		claimValue, ok := claims[rule.Claim]
		if !ok {
			debug("Rule %d: claim '%s' not found in token", i+1, rule.Claim)
			continue
		}

		debug("Rule %d: checking claim '%s' = '%v' against expected value '%s'", i+1, rule.Claim, claimValue, rule.Value)

		if m.matchesValue(claimValue, rule.Value) {
			debug("Rule %d: MATCH! Assigning roles: %v", i+1, rule.Roles)
			matched = true
			for _, role := range rule.Roles {
				roleSet[role] = struct{}{}
			}
		} else {
			debug("Rule %d: no match (claim value '%v' does not contain '%s')", i+1, claimValue, rule.Value)
		}
	}

	// If no rules matched, return default roles
	if !matched {
		debug("No RBAC rules matched, using default roles: %v", m.defaultRoles)
		return m.defaultRoles
	}

	// Convert set to slice
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	debug("RBAC evaluation complete. Assigned roles: %v", roles)
	return roles
}

// matchesValue checks if the claim value matches the expected value.
// It handles:
//   - String values: direct comparison or space-separated list (e.g., "group1 group2")
//   - Array values: checks if the expected value is in the array
func (m *Mapper) matchesValue(claimValue interface{}, expectedValue string) bool {
	debug("  matchesValue: type=%T, value=%v, expected=%s", claimValue, claimValue, expectedValue)

	switch v := claimValue.(type) {
	case string:
		// Check for exact match first
		if v == expectedValue {
			debug("  -> exact string match")
			return true
		}
		// Check if it's a space-separated list (common in some OIDC providers)
		parts := strings.Fields(v)
		if len(parts) > 1 {
			for _, part := range parts {
				if part == expectedValue {
					debug("  -> found in space-separated list")
					return true
				}
			}
		}
		debug("  -> string no match")
		return false
	case []interface{}:
		debug("  -> checking []interface{} with %d items", len(v))
		for i, item := range v {
			if s, ok := item.(string); ok {
				debug("    item %d: %s", i, s)
				if s == expectedValue {
					debug("    -> MATCH at index %d", i)
					return true
				}
			} else {
				debug("    item %d: not a string (type=%T)", i, item)
			}
		}
		debug("  -> no match in []interface{}")
	case []string:
		debug("  -> checking []string with %d items", len(v))
		for i, s := range v {
			debug("    item %d: %s", i, s)
			if s == expectedValue {
				debug("    -> MATCH at index %d", i)
				return true
			}
		}
		debug("  -> no match in []string")
	default:
		debug("  -> unknown type: %T", claimValue)
	}
	return false
}

// HasRules returns true if the mapper has any RBAC rules configured.
func (m *Mapper) HasRules() bool {
	return len(m.rules) > 0
}
