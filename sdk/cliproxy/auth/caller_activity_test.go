package auth

import (
	"testing"
	"time"
)

func TestCallerActivitySnapshotPrunesStaleEntries(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	now := time.Now()
	mgr.callerActivity["active-scope"] = now
	mgr.callerActivity["stale-scope"] = now.Add(-11 * time.Minute)

	snapshot := mgr.CallerActivitySnapshot([]string{"active-scope", "stale-scope", "missing-scope"})
	if got := snapshot["active-scope"]; got.IsZero() {
		t.Fatal("active-scope was pruned unexpectedly")
	}
	if got := snapshot["stale-scope"]; !got.IsZero() {
		t.Fatalf("stale-scope = %v, want zero", got)
	}
	if got := snapshot["missing-scope"]; !got.IsZero() {
		t.Fatalf("missing-scope = %v, want zero", got)
	}
}
