package auth

import (
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const callerActivityIdleThreshold = 10 * time.Minute

func (m *Manager) recordCallerActivity(opts cliproxyexecutor.Options) {
	if m == nil {
		return
	}
	scope := callerScopeFromMetadata(opts.Metadata)
	if scope == "" {
		return
	}
	now := time.Now()
	m.mu.Lock()
	if m.callerActivity == nil {
		m.callerActivity = make(map[string]time.Time)
	}
	m.callerActivity[scope] = now
	m.pruneCallerActivityLocked(now)
	m.mu.Unlock()
}

func (m *Manager) pruneCallerActivityLocked(now time.Time) {
	if m == nil || len(m.callerActivity) == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	for scope, seenAt := range m.callerActivity {
		if strings.TrimSpace(scope) == "" || seenAt.IsZero() || now.Sub(seenAt) > callerActivityIdleThreshold {
			delete(m.callerActivity, scope)
		}
	}
}

func (m *Manager) CallerActivitySnapshot(callerScopes []string) map[string]time.Time {
	result := make(map[string]time.Time, len(callerScopes))
	if m == nil || len(callerScopes) == 0 {
		return result
	}
	scopes := make(map[string]struct{}, len(callerScopes))
	for _, scope := range callerScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		scopes[scope] = struct{}{}
	}
	if len(scopes) == 0 {
		return result
	}

	now := time.Now()
	m.mu.Lock()
	m.pruneCallerActivityLocked(now)
	for scope := range scopes {
		if seenAt, ok := m.callerActivity[scope]; ok {
			result[scope] = seenAt
		}
	}
	m.mu.Unlock()
	return result
}
