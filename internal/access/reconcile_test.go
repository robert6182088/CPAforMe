package access

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestApplyAccessProvidersHotReloadsDisabledAPIKey(t *testing.T) {
	sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
	t.Cleanup(func() {
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
	})

	manager := sdkaccess.NewManager()
	initial := &config.Config{
		SDKConfig: config.SDKConfig{
			APIKeyEntries: []config.APIKeyEntry{{APIKey: "client-key", Alias: "Client"}},
		},
	}

	changed, errApply := ApplyAccessProviders(manager, nil, initial)
	if errApply != nil {
		t.Fatalf("ApplyAccessProviders(initial) error = %v", errApply)
	}
	if !changed {
		t.Fatal("ApplyAccessProviders(initial) changed = false, want true")
	}

	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer client-key")
	result, authErr := manager.Authenticate(context.Background(), req)
	if authErr != nil {
		t.Fatalf("Authenticate(initial) error = %v", authErr)
	}
	if result.Metadata["alias"] != "Client" {
		t.Fatalf("alias metadata = %q, want Client", result.Metadata["alias"])
	}

	updated := &config.Config{
		SDKConfig: config.SDKConfig{
			APIKeyEntries: []config.APIKeyEntry{{APIKey: "client-key", Alias: "Client", Disabled: true}},
		},
	}

	changed, errApply = ApplyAccessProviders(manager, initial, updated)
	if errApply != nil {
		t.Fatalf("ApplyAccessProviders(updated) error = %v", errApply)
	}
	if !changed {
		t.Fatal("ApplyAccessProviders(updated) changed = false, want true")
	}

	req = httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer client-key")
	_, authErr = manager.Authenticate(context.Background(), req)
	if !sdkaccess.IsAuthErrorCode(authErr, sdkaccess.AuthErrorCodeNoCredentials) {
		t.Fatalf("Authenticate(disabled) error = %v, want no credentials", authErr)
	}

	changed, errApply = ApplyAccessProviders(manager, updated, updated)
	if errApply != nil {
		t.Fatalf("ApplyAccessProviders(unchanged) error = %v", errApply)
	}
	if changed {
		t.Fatal("ApplyAccessProviders(unchanged) changed = true, want false")
	}
}
