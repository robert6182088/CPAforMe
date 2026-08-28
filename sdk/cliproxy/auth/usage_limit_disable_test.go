package auth

import (
	"context"
	"testing"
)

func TestIsUsageLimitReachedResultError(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want bool
	}{
		{name: "nested type", err: &Error{Message: `{"error":{"type":"usage_limit_reached"}}`}, want: true},
		{name: "direct code", err: &Error{Code: "usage_limit_reached"}, want: true},
		{name: "other type", err: &Error{Message: `{"error":{"type":"rate_limit_error"}}`}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUsageLimitReachedResultError(tt.err); got != tt.want {
				t.Fatalf("isUsageLimitReachedResultError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarkResultUsageLimitDisablesAuthAndReleasesCallerOwner(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	auth := callerExclusiveTestAuth("usage-limit-auth", "usage@example.com")
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	owner := callerExclusiveTestOptions("sk-owner")
	if !manager.claimAuthForCaller(auth, owner) {
		t.Fatal("claimAuthForCaller() = false, want true")
	}

	manager.MarkResult(ctx, Result{
		AuthID: auth.ID,
		Model:  "gpt-test",
		Error:  &Error{Message: `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached"}}`},
	})

	manager.mu.RLock()
	updated := manager.auths[auth.ID].Clone()
	manager.mu.RUnlock()
	if !updated.Disabled || updated.Status != StatusDisabled {
		t.Fatalf("auth disabled/status = %v/%s, want true/disabled", updated.Disabled, updated.Status)
	}
	resourceKey := callerExclusiveAuthResourceKey(updated)
	manager.mu.RLock()
	_, stillOwned := manager.callerExclusiveAuthOwners[resourceKey]
	manager.mu.RUnlock()
	if stillOwned {
		t.Fatal("usage-limited auth should release caller ownership")
	}
}
