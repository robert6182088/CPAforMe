package config

import "time"

const (
	defaultCallerExclusiveAuthTTL      = 72 * time.Hour
	defaultCallerExclusiveAuthTTLText  = "72h"
	defaultCallerExclusiveRedisAddr    = "127.0.0.1:6379"
	defaultCallerExclusiveRedisKeyPref = "cliproxy:caller-exclusive-auth"
)

// CallerExclusiveAuthConfig controls downstream API-key exclusive ownership of
// file-backed OAuth credentials.
type CallerExclusiveAuthConfig struct {
	// TTL controls how long a credential can stay exclusively occupied without
	// another successful use by the same downstream API key.
	TTL string `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// Redis optionally stores occupancy claims outside the process.
	Redis CallerExclusiveAuthRedisConfig `yaml:"redis,omitempty" json:"redis,omitempty"`
}

// CallerExclusiveAuthRedisConfig configures Redis-backed credential occupancy.
type CallerExclusiveAuthRedisConfig struct {
	Enabled   bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Addr      string `yaml:"addr,omitempty" json:"addr,omitempty"`
	Username  string `yaml:"username,omitempty" json:"username,omitempty"`
	Password  string `yaml:"password,omitempty" json:"password,omitempty"`
	DB        int    `yaml:"db,omitempty" json:"db,omitempty"`
	KeyPrefix string `yaml:"key-prefix,omitempty" json:"key-prefix,omitempty"`
}

// DefaultCallerExclusiveAuthConfig returns the default exclusive occupancy configuration.
func DefaultCallerExclusiveAuthConfig() CallerExclusiveAuthConfig {
	return CallerExclusiveAuthConfig{
		TTL: defaultCallerExclusiveAuthTTLText,
		Redis: CallerExclusiveAuthRedisConfig{
			Addr:      defaultCallerExclusiveRedisAddr,
			KeyPrefix: defaultCallerExclusiveRedisKeyPref,
		},
	}
}

// WithDefaults fills missing values while preserving explicit disabled Redis.
func (c CallerExclusiveAuthConfig) WithDefaults() CallerExclusiveAuthConfig {
	if c.TTL == "" {
		c.TTL = defaultCallerExclusiveAuthTTLText
	}
	if c.Redis.Addr == "" {
		c.Redis.Addr = defaultCallerExclusiveRedisAddr
	}
	if c.Redis.KeyPrefix == "" {
		c.Redis.KeyPrefix = defaultCallerExclusiveRedisKeyPref
	}
	return c
}

// TTLDuration resolves TTL to a positive duration, falling back to the default.
func (c CallerExclusiveAuthConfig) TTLDuration() time.Duration {
	parsed, err := time.ParseDuration(c.TTL)
	if err != nil || parsed <= 0 {
		return defaultCallerExclusiveAuthTTL
	}
	return parsed
}
