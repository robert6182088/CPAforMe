package auth

import (
	"context"
	"errors"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
)

func callerExclusiveTestOptions(apiKey string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: cliproxysession.CallerScope(apiKey),
		},
	}
}

func callerExclusiveTestAuth(id, email string) *Auth {
	return &Auth{
		ID:       id,
		Provider: "codex",
		FileName: id + ".json",
		Status:   StatusActive,
		Metadata: map[string]any{
			"access_token": "token-" + id,
			"email":        email,
		},
	}
}

func TestManagerCallerExclusiveAuthKeepsFillFirstAssignmentsPerAPIKey(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})

	for _, auth := range []*Auth{
		callerExclusiveTestAuth("auth-a", "aaronbrown753906+oclymm8lbm7h@outlook.com"),
		callerExclusiveTestAuth("auth-b", "other@example.com"),
	} {
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatalf("Register(%q) error = %v", auth.ID, errRegister)
		}
	}

	zhangsan := callerExclusiveTestOptions("sk-zhangsan")
	lisi := callerExclusiveTestOptions("sk-lisi")

	gotZhangsan, _, errPickZhangsan := manager.pickNext(ctx, "codex", "", zhangsan, nil)
	if errPickZhangsan != nil {
		t.Fatalf("pickNext(zhangsan) error = %v", errPickZhangsan)
	}
	if gotZhangsan == nil || gotZhangsan.ID != "auth-a" {
		t.Fatalf("pickNext(zhangsan) auth = %#v, want auth-a", gotZhangsan)
	}

	gotLisi, _, errPickLisi := manager.pickNext(ctx, "codex", "", lisi, nil)
	if errPickLisi != nil {
		t.Fatalf("pickNext(lisi) error = %v", errPickLisi)
	}
	if gotLisi == nil || gotLisi.ID != "auth-b" {
		t.Fatalf("pickNext(lisi) auth = %#v, want auth-b", gotLisi)
	}

	gotZhangsanAgain, _, errPickZhangsanAgain := manager.pickNext(ctx, "codex", "", zhangsan, nil)
	if errPickZhangsanAgain != nil {
		t.Fatalf("pickNext(zhangsan again) error = %v", errPickZhangsanAgain)
	}
	if gotZhangsanAgain == nil || gotZhangsanAgain.ID != "auth-a" {
		t.Fatalf("pickNext(zhangsan again) auth = %#v, want auth-a", gotZhangsanAgain)
	}
}

func TestManagerCallerExclusiveAuthTreatsSameAccountAsSameResource(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})

	for _, auth := range []*Auth{
		callerExclusiveTestAuth("auth-a", "same@example.com"),
		callerExclusiveTestAuth("auth-b", "same@example.com"),
	} {
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatalf("Register(%q) error = %v", auth.ID, errRegister)
		}
	}

	if got, _, errPick := manager.pickNext(ctx, "codex", "", callerExclusiveTestOptions("sk-zhangsan"), nil); errPick != nil || got == nil || got.ID != "auth-a" {
		t.Fatalf("pickNext(zhangsan) = %#v, %v; want auth-a", got, errPick)
	}

	got, _, errPick := manager.pickNext(ctx, "codex", "", callerExclusiveTestOptions("sk-lisi"), nil)
	if got != nil {
		t.Fatalf("pickNext(lisi) auth = %#v, want nil", got)
	}
	var authErr *Error
	if !errors.As(errPick, &authErr) || authErr.Code != "auth_not_found" {
		t.Fatalf("pickNext(lisi) error = %#v, want auth_not_found", errPick)
	}
}

func TestManagerCallerExclusiveAuthReleasesDisabledAPIKeyClaimsOnConfigUpdate(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})

	if _, err := manager.Register(ctx, callerExclusiveTestAuth("auth-a", "same@example.com")); err != nil {
		t.Fatalf("Register(auth-a) error = %v", err)
	}

	zhangsan := callerExclusiveTestOptions("sk-zhangsan")
	lisi := callerExclusiveTestOptions("sk-lisi")
	if got, _, errPick := manager.pickNext(ctx, "codex", "", zhangsan, nil); errPick != nil || got == nil || got.ID != "auth-a" {
		t.Fatalf("pickNext(zhangsan) = %#v, %v; want auth-a", got, errPick)
	}

	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyEntries: []internalconfig.APIKeyEntry{
			{APIKey: "sk-zhangsan", Disabled: true},
			{APIKey: "sk-lisi"},
		},
	}})

	got, _, errPick := manager.pickNext(ctx, "codex", "", lisi, nil)
	if errPick != nil {
		t.Fatalf("pickNext(lisi) error = %v", errPick)
	}
	if got == nil || got.ID != "auth-a" {
		t.Fatalf("pickNext(lisi) auth = %#v, want released auth-a", got)
	}
}
