package config

import "strings"

// SanitizeAccessAPIKeys normalizes legacy and structured client API key lists.
func (cfg *Config) SanitizeAccessAPIKeys() {
	if cfg == nil {
		return
	}
	cfg.APIKeys = NormalizeAPIKeys(cfg.APIKeys)
	cfg.APIKeyEntries = NormalizeAPIKeyEntries(cfg.APIKeyEntries)
}

// NormalizeAPIKeys trims, drops empty keys, and removes duplicates.
func NormalizeAPIKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeAPIKeyEntries trims, drops empty keys, and removes duplicate entries.
func NormalizeAPIKeyEntries(entries []APIKeyEntry) []APIKeyEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]APIKeyEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		entry.APIKey = strings.TrimSpace(entry.APIKey)
		if entry.APIKey == "" {
			continue
		}
		if _, exists := seen[entry.APIKey]; exists {
			continue
		}
		seen[entry.APIKey] = struct{}{}
		entry.Alias = strings.TrimSpace(entry.Alias)
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// AccessAPIKeyEntries returns the structured API key list used for management display.
func (cfg *SDKConfig) AccessAPIKeyEntries() []APIKeyEntry {
	if cfg == nil {
		return nil
	}
	if len(cfg.APIKeyEntries) > 0 {
		return NormalizeAPIKeyEntries(cfg.APIKeyEntries)
	}
	keys := NormalizeAPIKeys(cfg.APIKeys)
	if len(keys) == 0 {
		return nil
	}
	entries := make([]APIKeyEntry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, APIKeyEntry{APIKey: key})
	}
	return entries
}

// EffectiveAPIKeys returns enabled client API keys used for request authentication.
func (cfg *SDKConfig) EffectiveAPIKeys() []string {
	entries := cfg.AccessAPIKeyEntries()
	if len(entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Disabled {
			continue
		}
		keys = append(keys, entry.APIKey)
	}
	return NormalizeAPIKeys(keys)
}
