package rbac

import (
	"reflect"
	"sort"
	"testing"

	"github.com/qjoly/talosctl-oidc/pkg/config"
)

func TestMapRoles_NoRules(t *testing.T) {
	// When no rules are configured, default roles should be returned.
	defaultRoles := []string{"os:admin"}
	mapper := NewMapper(nil, defaultRoles)

	claims := map[string]interface{}{
		"sub":    "user123",
		"email":  "user@example.com",
		"groups": []string{"developers"},
	}

	roles := mapper.MapRoles(claims)

	if !reflect.DeepEqual(roles, defaultRoles) {
		t.Errorf("expected %v, got %v", defaultRoles, roles)
	}
}

func TestMapRoles_SingleMatch(t *testing.T) {
	rules := []config.RBACRule{
		{
			Claim: "groups",
			Value: "platform-admins",
			Roles: []string{"os:admin"},
		},
		{
			Claim: "groups",
			Value: "developers",
			Roles: []string{"os:reader"},
		},
	}
	defaultRoles := []string{"os:admin"}
	mapper := NewMapper(rules, defaultRoles)

	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []string{"developers"},
	}

	roles := mapper.MapRoles(claims)
	expected := []string{"os:reader"}

	if !reflect.DeepEqual(sorted(roles), sorted(expected)) {
		t.Errorf("expected %v, got %v", expected, roles)
	}
}

func TestMapRoles_MultipleMatches(t *testing.T) {
	rules := []config.RBACRule{
		{
			Claim: "groups",
			Value: "platform-admins",
			Roles: []string{"os:admin"},
		},
		{
			Claim: "groups",
			Value: "developers",
			Roles: []string{"os:reader"},
		},
		{
			Claim: "groups",
			Value: "auditors",
			Roles: []string{"os:reader"},
		},
	}
	defaultRoles := []string{"os:admin"}
	mapper := NewMapper(rules, defaultRoles)

	// User is in both platform-admins and developers
	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []string{"platform-admins", "developers"},
	}

	roles := mapper.MapRoles(claims)
	expected := []string{"os:admin", "os:reader"}

	if !reflect.DeepEqual(sorted(roles), sorted(expected)) {
		t.Errorf("expected %v, got %v", expected, roles)
	}
}

func TestMapRoles_NoMatch(t *testing.T) {
	rules := []config.RBACRule{
		{
			Claim: "groups",
			Value: "platform-admins",
			Roles: []string{"os:admin"},
		},
	}
	defaultRoles := []string{"os:reader"}
	mapper := NewMapper(rules, defaultRoles)

	// User is in a group that doesn't match any rule
	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []string{"unknown-group"},
	}

	roles := mapper.MapRoles(claims)

	// Should return default roles when no rules match
	if !reflect.DeepEqual(roles, defaultRoles) {
		t.Errorf("expected %v (default), got %v", defaultRoles, roles)
	}
}

func TestMapRoles_StringClaim(t *testing.T) {
	rules := []config.RBACRule{
		{
			Claim: "role",
			Value: "admin",
			Roles: []string{"os:admin"},
		},
		{
			Claim: "role",
			Value: "user",
			Roles: []string{"os:reader"},
		},
	}
	defaultRoles := []string{"os:admin"}
	mapper := NewMapper(rules, defaultRoles)

	claims := map[string]interface{}{
		"sub":  "user123",
		"role": "admin",
	}

	roles := mapper.MapRoles(claims)
	expected := []string{"os:admin"}

	if !reflect.DeepEqual(roles, expected) {
		t.Errorf("expected %v, got %v", expected, roles)
	}
}

func TestMapRoles_MissingClaim(t *testing.T) {
	rules := []config.RBACRule{
		{
			Claim: "groups",
			Value: "platform-admins",
			Roles: []string{"os:admin"},
		},
	}
	defaultRoles := []string{"os:reader"}
	mapper := NewMapper(rules, defaultRoles)

	// User doesn't have the 'groups' claim
	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
	}

	roles := mapper.MapRoles(claims)

	// Should return default roles when claim is missing
	if !reflect.DeepEqual(roles, defaultRoles) {
		t.Errorf("expected %v (default), got %v", defaultRoles, roles)
	}
}

func TestMapRoles_EmptyRoles(t *testing.T) {
	rules := []config.RBACRule{
		{
			Claim: "groups",
			Value: "platform-admins",
			Roles: []string{},
		},
	}
	defaultRoles := []string{"os:admin"}
	mapper := NewMapper(rules, defaultRoles)

	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []string{"platform-admins"},
	}

	roles := mapper.MapRoles(claims)

	// Should return empty roles since rule matched but has no roles defined
	if len(roles) != 0 {
		t.Errorf("expected empty roles, got %v", roles)
	}
}

func TestHasRules(t *testing.T) {
	// Mapper with rules
	mapperWithRules := NewMapper([]config.RBACRule{
		{Claim: "groups", Value: "admins", Roles: []string{"os:admin"}},
	}, []string{"os:reader"})

	if !mapperWithRules.HasRules() {
		t.Error("expected HasRules() to return true when rules are configured")
	}

	// Mapper without rules
	mapperWithoutRules := NewMapper(nil, []string{"os:admin"})

	if mapperWithoutRules.HasRules() {
		t.Error("expected HasRules() to return false when no rules are configured")
	}
}

func TestMatchesValue_ArrayInterface(t *testing.T) {
	mapper := NewMapper(nil, []string{"os:admin"})

	// Test with []interface{} (as returned from JSON unmarshaling)
	claimValue := []interface{}{"group1", "group2", "developers"}

	if !mapper.matchesValue(claimValue, "developers") {
		t.Error("expected matchesValue to return true for value in array")
	}

	if mapper.matchesValue(claimValue, "nonexistent") {
		t.Error("expected matchesValue to return false for value not in array")
	}
}

func TestMatchesValue_ArrayString(t *testing.T) {
	mapper := NewMapper(nil, []string{"os:admin"})

	// Test with []string
	claimValue := []string{"group1", "group2", "developers"}

	if !mapper.matchesValue(claimValue, "developers") {
		t.Error("expected matchesValue to return true for value in array")
	}

	if mapper.matchesValue(claimValue, "nonexistent") {
		t.Error("expected matchesValue to return false for value not in array")
	}
}

func TestMatchesValue_SpaceSeparatedString(t *testing.T) {
	mapper := NewMapper(nil, []string{"os:admin"})

	// Test with space-separated string (common in some OIDC providers like Authentik)
	claimValue := "authentik Admins Hypervisors Tech Family Omni"

	if !mapper.matchesValue(claimValue, "Admins") {
		t.Error("expected matchesValue to return true for value in space-separated string")
	}

	if !mapper.matchesValue(claimValue, "Hypervisors") {
		t.Error("expected matchesValue to return true for value in space-separated string")
	}

	if mapper.matchesValue(claimValue, "NonExistent") {
		t.Error("expected matchesValue to return false for value not in space-separated string")
	}

	// Single value should still work
	singleValue := "platform-admins"
	if !mapper.matchesValue(singleValue, "platform-admins") {
		t.Error("expected matchesValue to return true for exact string match")
	}

	if mapper.matchesValue(singleValue, "other-group") {
		t.Error("expected matchesValue to return false for non-matching string")
	}
}

// Helper function to sort strings for comparison
func sorted(s []string) []string {
	result := make([]string, len(s))
	copy(result, s)
	sort.Strings(result)
	return result
}
