package handler

import (
	"reflect"
	"testing"
)

func managedRealityCompatibilityRequest(security string, realitySettings map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"inbound": map[string]interface{}{
			"protocol": "vless",
			"streamSettings": map[string]interface{}{
				"security":        security,
				"realitySettings": realitySettings,
			},
		},
	}
}

func TestApplyManagedRealityCompatibilityDefaultsOnlyMissingOrBlankValue(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings map[string]interface{}
	}{
		{name: "missing", settings: map[string]interface{}{}},
		{name: "null", settings: map[string]interface{}{"minClientVer": nil}},
		{name: "empty", settings: map[string]interface{}{"minClientVer": ""}},
		{name: "whitespace", settings: map[string]interface{}{"minClientVer": "  \t"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := managedRealityCompatibilityRequest(" ReAlItY ", test.settings)
			applyManagedRealityCompatibility(request)

			if got := test.settings["minClientVer"]; got != managedRealityMinClientVersion {
				t.Fatalf("minClientVer = %#v, want %q", got, managedRealityMinClientVersion)
			}
		})
	}
}

func TestApplyManagedRealityCompatibilityPreservesExplicitValue(t *testing.T) {
	for _, test := range []struct {
		name     string
		existing interface{}
	}{
		{name: "custom lower version", existing: "1.0.1"},
		{name: "custom current version", existing: "26.3.27"},
		{name: "invalid value remains visible to Xray validation", existing: map[string]interface{}{"unexpected": true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := map[string]interface{}{"minClientVer": test.existing}
			request := managedRealityCompatibilityRequest("reality", settings)
			applyManagedRealityCompatibility(request)

			if got := settings["minClientVer"]; !reflect.DeepEqual(got, test.existing) {
				t.Fatalf("minClientVer = %#v, want preserved %#v", got, test.existing)
			}
		})
	}
}

func TestApplyManagedRealityCompatibilityLeavesOtherInboundsUntouched(t *testing.T) {
	plain := managedRealityCompatibilityRequest("tls", map[string]interface{}{})
	applyManagedRealityCompatibility(plain)
	plainSettings := plain["inbound"].(map[string]interface{})["streamSettings"].(map[string]interface{})["realitySettings"].(map[string]interface{})
	if _, exists := plainSettings["minClientVer"]; exists {
		t.Fatal("non-REALITY inbound unexpectedly received minClientVer")
	}

	missingSettings := map[string]interface{}{
		"inbound": map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "reality"},
		},
	}
	applyManagedRealityCompatibility(missingSettings)
	stream := missingSettings["inbound"].(map[string]interface{})["streamSettings"].(map[string]interface{})
	if _, exists := stream["realitySettings"]; exists {
		t.Fatal("missing realitySettings was unexpectedly synthesized")
	}
}
