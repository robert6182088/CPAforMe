package configaccess

import (
	"context"
	"net/http/httptest"
	"testing"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestProviderUsesStructuredAPIKeyEntries(t *testing.T) {
	p := newProvider("test", []sdkconfig.APIKeyEntry{
		{APIKey: "active-key", Alias: "Team A"},
		{APIKey: "disabled-key", Alias: "Old", Disabled: true},
	})

	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer active-key")
	result, authErr := p.Authenticate(context.Background(), req)
	if authErr != nil {
		t.Fatalf("Authenticate(active) error = %v", authErr)
	}
	if result.Principal != "active-key" {
		t.Fatalf("principal = %q, want active-key", result.Principal)
	}
	if result.Metadata["alias"] != "Team A" {
		t.Fatalf("alias metadata = %q, want Team A", result.Metadata["alias"])
	}

	req = httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer disabled-key")
	_, authErr = p.Authenticate(context.Background(), req)
	if !sdkaccess.IsAuthErrorCode(authErr, sdkaccess.AuthErrorCodeInvalidCredential) {
		t.Fatalf("Authenticate(disabled) error = %v, want invalid credential", authErr)
	}
}
