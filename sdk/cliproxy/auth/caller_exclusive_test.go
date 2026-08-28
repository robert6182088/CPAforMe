package auth

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestManagerCallerExclusiveAuthSnapshotOrdersLatestClaimFirst(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.auths = map[string]*Auth{
		"auth-old": callerExclusiveTestAuth("auth-old", "old@example.com"),
		"auth-new": callerExclusiveTestAuth("auth-new", "new@example.com"),
	}
	zhangsanScope := cliproxysession.CallerScope("sk-zhangsan")
	manager.callerExclusiveAuthOwners = map[string]callerExclusiveOwnerRecord{
		callerExclusiveAuthResourceKey(manager.auths["auth-old"]): {Owner: zhangsanScope, Sequence: 1, ClaimedAt: time.Now().Add(-time.Hour)},
		callerExclusiveAuthResourceKey(manager.auths["auth-new"]): {Owner: zhangsanScope, Sequence: 2, ClaimedAt: time.Now()},
	}

	snapshot := manager.CallerAuthOccupancySnapshot([]string{zhangsanScope})
	items := snapshot[zhangsanScope]
	if len(items) != 2 {
		t.Fatalf("items len = %d, want 2: %#v", len(items), items)
	}
	if got := items[0].Name; got != "auth-new.json" {
		t.Fatalf("latest item name = %q, want auth-new.json", got)
	}
	if got := items[0].ClaimSequence; got != 2 {
		t.Fatalf("latest item sequence = %d, want 2", got)
	}
	if got := items[1].Name; got != "auth-old.json" {
		t.Fatalf("older item name = %q, want auth-old.json", got)
	}
}

func TestManagerCallerExclusiveAuthPrunesExpiredClaims(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := callerExclusiveTestAuth("auth-old", "old@example.com")
	manager.auths = map[string]*Auth{
		auth.ID: auth,
	}
	zhangsanScope := cliproxysession.CallerScope("sk-zhangsan")
	manager.callerExclusiveAuthOwners = map[string]callerExclusiveOwnerRecord{
		callerExclusiveAuthResourceKey(auth): {Owner: zhangsanScope, Sequence: 1, ClaimedAt: time.Now().Add(-(callerExclusiveAuthTTL + time.Hour))},
	}

	snapshot := manager.CallerAuthOccupancySnapshot([]string{zhangsanScope})
	if items := snapshot[zhangsanScope]; len(items) != 0 {
		t.Fatalf("items len = %d, want 0 after expiry: %#v", len(items), items)
	}
	if len(manager.callerExclusiveAuthOwners) != 0 {
		t.Fatalf("owners len = %d, want 0 after expiry cleanup", len(manager.callerExclusiveAuthOwners))
	}
}

func TestManagerCallerExclusiveAuthUsesConfiguredTTL(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := callerExclusiveTestAuth("auth-old", "old@example.com")
	manager.auths = map[string]*Auth{
		auth.ID: auth,
	}
	zhangsanScope := cliproxysession.CallerScope("sk-zhangsan")
	manager.callerExclusiveAuthOwners = map[string]callerExclusiveOwnerRecord{
		callerExclusiveAuthResourceKey(auth): {Owner: zhangsanScope, Sequence: 1, ClaimedAt: time.Now().Add(-2 * time.Hour)},
	}

	manager.SetConfig(&internalconfig.Config{
		CallerExclusiveAuth: internalconfig.CallerExclusiveAuthConfig{TTL: "1h"},
		SDKConfig: internalconfig.SDKConfig{
			APIKeyEntries: []internalconfig.APIKeyEntry{{APIKey: "sk-zhangsan"}},
		},
	})

	snapshot := manager.CallerAuthOccupancySnapshot([]string{zhangsanScope})
	if items := snapshot[zhangsanScope]; len(items) != 0 {
		t.Fatalf("items len = %d, want 0 after configured expiry: %#v", len(items), items)
	}
}

func TestManagerCallerExclusiveAuthReleasesDisabledAuthClaimsOnUpdate(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})

	auth := callerExclusiveTestAuth("auth-a", "same@example.com")
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("Register(auth-a) error = %v", err)
	}

	zhangsan := callerExclusiveTestOptions("sk-zhangsan")
	if got, _, errPick := manager.pickNext(ctx, "codex", "", zhangsan, nil); errPick != nil || got == nil || got.ID != "auth-a" {
		t.Fatalf("pickNext(zhangsan) = %#v, %v; want auth-a", got, errPick)
	}

	disabled := auth.Clone()
	disabled.Disabled = true
	disabled.Status = StatusDisabled
	if _, errUpdate := manager.Update(ctx, disabled); errUpdate != nil {
		t.Fatalf("Update(disabled) error = %v", errUpdate)
	}

	zhangsanScope := cliproxysession.CallerScope("sk-zhangsan")
	snapshot := manager.CallerAuthOccupancySnapshot([]string{zhangsanScope})
	if items := snapshot[zhangsanScope]; len(items) != 0 {
		t.Fatalf("items len = %d, want 0 after auth disabled: %#v", len(items), items)
	}
}

func TestManagerCallerExclusiveAuthRefreshesClaimTimeForSameOwner(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := callerExclusiveTestAuth("auth-a", "a@example.com")
	resourceKey := callerExclusiveAuthResourceKey(auth)
	oldClaimedAt := time.Now().Add(-(callerExclusiveAuthTTL - time.Hour))
	zhangsanScope := cliproxysession.CallerScope("sk-zhangsan")
	manager.callerExclusiveAuthOwners = map[string]callerExclusiveOwnerRecord{
		resourceKey: {Owner: zhangsanScope, Sequence: 1, ClaimedAt: oldClaimedAt},
	}
	manager.callerExclusiveAuthSeq.Store(1)

	if !manager.claimAuthForCaller(auth, callerExclusiveTestOptions("sk-zhangsan")) {
		t.Fatal("claimAuthForCaller() = false, want true for same owner")
	}
	state := manager.callerExclusiveAuthOwners[resourceKey]
	if !state.ClaimedAt.After(oldClaimedAt) {
		t.Fatalf("claimedAt = %s, want after %s", state.ClaimedAt, oldClaimedAt)
	}
	if state.Sequence <= 1 {
		t.Fatalf("sequence = %d, want refreshed sequence > 1", state.Sequence)
	}
}
