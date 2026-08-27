package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPatchAPIKeysAliasAndDisabled(t *testing.T) {
	cfg := &config.Config{SDKConfig: config.SDKConfig{
		APIKeys: []string{"legacy-key"},
	}}
	h := &Handler{cfg: cfg, configFilePath: writeTestConfigFile(t)}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/api-keys", strings.NewReader(`{"index":0,"value":{"alias":"Team A","disabled":true}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.PatchAPIKeys(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(cfg.APIKeyEntries) != 1 {
		t.Fatalf("APIKeyEntries len = %d, want 1", len(cfg.APIKeyEntries))
	}
	if got := cfg.APIKeyEntries[0].Alias; got != "Team A" {
		t.Fatalf("alias = %q, want Team A", got)
	}
	if !cfg.APIKeyEntries[0].Disabled {
		t.Fatal("disabled = false, want true")
	}
	if keys := cfg.EffectiveAPIKeys(); len(keys) != 0 {
		t.Fatalf("EffectiveAPIKeys() = %+v, want empty", keys)
	}
}

func TestGetAPIKeysReturnsStructuredEntries(t *testing.T) {
	cfg := &config.Config{SDKConfig: config.SDKConfig{
		APIKeyEntries: []config.APIKeyEntry{
			{APIKey: "active-key", Alias: "Team A"},
			{APIKey: "disabled-key", Alias: "Old", Disabled: true},
		},
	}}
	h := &Handler{cfg: cfg, configFilePath: writeTestConfigFile(t)}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/api-keys", nil)
	h.GetAPIKeys(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		APIKeys       []string             `json:"api-keys"`
		APIKeyEntries []config.APIKeyEntry `json:"api-key-entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.APIKeys) != 2 {
		t.Fatalf("api-keys len = %d, want 2", len(payload.APIKeys))
	}
	if len(payload.APIKeyEntries) != 2 || !payload.APIKeyEntries[1].Disabled {
		t.Fatalf("api-key-entries = %+v, want disabled second entry", payload.APIKeyEntries)
	}
}

func TestPutConfigYAMLTriggersRuntimeReload(t *testing.T) {
	cfg := &config.Config{SDKConfig: config.SDKConfig{
		APIKeys: []string{"old-key"},
	}}
	h := &Handler{cfg: cfg, configFilePath: writeTestConfigFile(t)}
	reloads := make(chan *config.Config, 1)
	done := make(chan struct{})
	h.SetConfigReloadHook(func(ctx context.Context, cfg *config.Config) {
		defer close(done)
		if ctx == nil {
			t.Error("reload context is nil")
		}
		reloads <- cfg
	})

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/config.yaml", strings.NewReader("api-key-entries:\n  - api-key: yaml-key\n    alias: YAML Alias\n    disabled: true\n"))
	ctx.Request.Header.Set("Content-Type", "application/yaml")
	h.PutConfigYAML(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	waitForReloadDone(t, done)
	reloaded := <-reloads
	if len(reloaded.APIKeyEntries) != 1 {
		t.Fatalf("APIKeyEntries len = %d, want 1", len(reloaded.APIKeyEntries))
	}
	if got := reloaded.APIKeyEntries[0].Alias; got != "YAML Alias" {
		t.Fatalf("alias = %q, want YAML Alias", got)
	}
	if !reloaded.APIKeyEntries[0].Disabled {
		t.Fatal("disabled = false, want true")
	}
}
