package config

import "testing"

func TestAccessAPIKeyEntriesFallbackAndEffectiveKeys(t *testing.T) {
	cfg := &Config{SDKConfig: SDKConfig{
		APIKeys: []string{" legacy-key ", "legacy-key", " "},
	}}

	entries := cfg.AccessAPIKeyEntries()
	if len(entries) != 1 || entries[0].APIKey != "legacy-key" {
		t.Fatalf("AccessAPIKeyEntries() = %+v, want one legacy-key entry", entries)
	}
	if keys := cfg.EffectiveAPIKeys(); len(keys) != 1 || keys[0] != "legacy-key" {
		t.Fatalf("EffectiveAPIKeys() = %+v, want [legacy-key]", keys)
	}
}

func TestStructuredAPIKeyEntriesOverrideLegacyKeys(t *testing.T) {
	cfg := &Config{SDKConfig: SDKConfig{
		APIKeys: []string{"legacy-key"},
		APIKeyEntries: []APIKeyEntry{
			{APIKey: " active-key ", Alias: " Team A "},
			{APIKey: "disabled-key", Disabled: true},
		},
	}}
	cfg.SanitizeAccessAPIKeys()

	entries := cfg.AccessAPIKeyEntries()
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2: %+v", len(entries), entries)
	}
	if entries[0].Alias != "Team A" {
		t.Fatalf("alias = %q, want Team A", entries[0].Alias)
	}
	keys := cfg.EffectiveAPIKeys()
	if len(keys) != 1 || keys[0] != "active-key" {
		t.Fatalf("EffectiveAPIKeys() = %+v, want [active-key]", keys)
	}
}

func TestParseConfigStructuredAPIKeyEntries(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
api-keys:
  - legacy-key
api-key-entries:
  - api-key: active-key
    alias: Team A
  - api-key: disabled-key
    alias: Old
    disabled: true
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}

	keys := cfg.EffectiveAPIKeys()
	if len(keys) != 1 || keys[0] != "active-key" {
		t.Fatalf("EffectiveAPIKeys() = %+v, want [active-key]", keys)
	}
	if len(cfg.APIKeyEntries) != 2 {
		t.Fatalf("APIKeyEntries len = %d, want 2", len(cfg.APIKeyEntries))
	}
}
