package auth

import (
	"sort"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
)

// CallerAuthOccupancy describes one auth file account currently owned by a downstream API key.
type CallerAuthOccupancy struct {
	AuthID        string    `json:"auth_id"`
	AuthIndex     string    `json:"auth_index,omitempty"`
	Name          string    `json:"name"`
	Label         string    `json:"label,omitempty"`
	Provider      string    `json:"provider"`
	AccountType   string    `json:"account_type,omitempty"`
	Account       string    `json:"account,omitempty"`
	Status        Status    `json:"status"`
	StatusMessage string    `json:"status_message,omitempty"`
	Disabled      bool      `json:"disabled"`
	Unavailable   bool      `json:"unavailable"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

func callerScopeFromMetadata(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	value, _ := metadata[cliproxyexecutor.CallerScopeMetadataKey].(string)
	return strings.TrimSpace(value)
}

func callerExclusiveAuthResourceKey(auth *Auth) string {
	if !callerExclusiveAuthEligible(auth) {
		return ""
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	accountType, account := auth.AccountInfo()
	accountType = strings.ToLower(strings.TrimSpace(accountType))
	account = strings.ToLower(strings.TrimSpace(account))
	if provider != "" && accountType != "" && account != "" {
		return provider + "|" + accountType + "|" + account
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return ""
	}
	return "auth-id|" + authID
}

func callerExclusiveAuthEligible(auth *Auth) bool {
	if auth == nil || auth.AuthKind() != AuthKindOAuth {
		return false
	}
	switch auth.AuthSourceKind() {
	case AuthSourceFile, AuthSourceGit, AuthSourceObjectStore, AuthSourcePostgres:
		return true
	default:
		return false
	}
}

func (m *Manager) withCallerExclusiveTried(opts cliproxyexecutor.Options, tried map[string]struct{}) map[string]struct{} {
	if m == nil {
		return tried
	}
	callerScope := callerScopeFromMetadata(opts.Metadata)
	if callerScope == "" {
		return tried
	}
	m.mu.RLock()
	if len(m.callerExclusiveAuthOwners) == 0 {
		m.mu.RUnlock()
		return tried
	}
	excluded := make([]string, 0)
	for _, auth := range m.auths {
		if auth == nil || strings.TrimSpace(auth.ID) == "" {
			continue
		}
		resourceKey := callerExclusiveAuthResourceKey(auth)
		if resourceKey == "" {
			continue
		}
		owner := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey])
		if owner == "" || owner == callerScope {
			continue
		}
		excluded = append(excluded, auth.ID)
	}
	m.mu.RUnlock()

	if len(excluded) == 0 {
		return tried
	}
	if tried == nil {
		tried = make(map[string]struct{}, len(excluded))
	}
	for _, authID := range excluded {
		tried[authID] = struct{}{}
	}
	return tried
}

func (m *Manager) authAllowedForCallerLocked(auth *Auth, callerScope string) bool {
	if m == nil || auth == nil || len(m.callerExclusiveAuthOwners) == 0 {
		return true
	}
	callerScope = strings.TrimSpace(callerScope)
	if callerScope == "" {
		return true
	}
	resourceKey := callerExclusiveAuthResourceKey(auth)
	if resourceKey == "" {
		return true
	}
	owner := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey])
	return owner == "" || owner == callerScope
}

func (m *Manager) claimAuthForCaller(auth *Auth, opts cliproxyexecutor.Options) bool {
	if m == nil || auth == nil {
		return true
	}
	callerScope := callerScopeFromMetadata(opts.Metadata)
	if callerScope == "" {
		return true
	}
	resourceKey := callerExclusiveAuthResourceKey(auth)
	if resourceKey == "" {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.callerExclusiveAuthOwners == nil {
		m.callerExclusiveAuthOwners = make(map[string]string)
	}
	if existing := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey]); existing == "" {
		m.callerExclusiveAuthOwners[resourceKey] = callerScope
		return true
	} else if existing != callerScope {
		return false
	}
	return true
}

func (m *Manager) moveCallerExclusiveOwnerLocked(oldAuth, newAuth *Auth) {
	if m == nil || len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	oldKey := callerExclusiveAuthResourceKey(oldAuth)
	newKey := callerExclusiveAuthResourceKey(newAuth)
	if oldKey == "" || oldKey == newKey {
		return
	}
	owner := strings.TrimSpace(m.callerExclusiveAuthOwners[oldKey])
	if owner != "" && newKey != "" && strings.TrimSpace(m.callerExclusiveAuthOwners[newKey]) == "" {
		m.callerExclusiveAuthOwners[newKey] = owner
	}
	m.deleteCallerExclusiveOwnerIfUnusedLocked(oldKey)
}

func (m *Manager) deleteCallerExclusiveOwnerIfUnusedLocked(resourceKey string) {
	if m == nil || resourceKey == "" || len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	for _, auth := range m.auths {
		if callerExclusiveAuthResourceKey(auth) == resourceKey {
			return
		}
	}
	delete(m.callerExclusiveAuthOwners, resourceKey)
}

func (m *Manager) pruneCallerExclusiveOwnersLocked() {
	if m == nil || len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	activeKeys := make(map[string]struct{}, len(m.auths))
	for _, auth := range m.auths {
		if resourceKey := callerExclusiveAuthResourceKey(auth); resourceKey != "" {
			activeKeys[resourceKey] = struct{}{}
		}
	}
	for resourceKey := range m.callerExclusiveAuthOwners {
		if _, ok := activeKeys[resourceKey]; !ok {
			delete(m.callerExclusiveAuthOwners, resourceKey)
		}
	}
}

func (m *Manager) pruneCallerExclusiveOwnersForConfig(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	enabledScopes := make(map[string]struct{})
	if cfg != nil {
		for _, entry := range cfg.AccessAPIKeyEntries() {
			if entry.Disabled {
				continue
			}
			if scope := cliproxysession.CallerScope(entry.APIKey); scope != "" {
				enabledScopes[scope] = struct{}{}
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	if len(enabledScopes) == 0 {
		clear(m.callerExclusiveAuthOwners)
		return
	}
	for resourceKey, owner := range m.callerExclusiveAuthOwners {
		if _, ok := enabledScopes[strings.TrimSpace(owner)]; !ok {
			delete(m.callerExclusiveAuthOwners, resourceKey)
		}
	}
}

// CallerAuthOccupancySnapshot returns auth file accounts owned by each supplied caller scope.
func (m *Manager) CallerAuthOccupancySnapshot(callerScopes []string) map[string][]CallerAuthOccupancy {
	result := make(map[string][]CallerAuthOccupancy, len(callerScopes))
	if m == nil || len(callerScopes) == 0 {
		return result
	}
	allowed := make(map[string]struct{}, len(callerScopes))
	for _, scope := range callerScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		allowed[scope] = struct{}{}
		result[scope] = nil
	}
	if len(allowed) == 0 {
		return result
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		resourceKey := callerExclusiveAuthResourceKey(auth)
		if resourceKey == "" {
			continue
		}
		owner := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey])
		if _, ok := allowed[owner]; !ok {
			continue
		}
		result[owner] = append(result[owner], callerAuthOccupancyFromAuth(auth))
	}
	for scope := range result {
		sort.Slice(result[scope], func(i, j int) bool {
			left := strings.ToLower(result[scope][i].Provider + "|" + result[scope][i].Name + "|" + result[scope][i].AuthID)
			right := strings.ToLower(result[scope][j].Provider + "|" + result[scope][j].Name + "|" + result[scope][j].AuthID)
			return left < right
		})
	}
	return result
}

func callerAuthOccupancyFromAuth(auth *Auth) CallerAuthOccupancy {
	name := strings.TrimSpace(auth.FileName)
	if name == "" {
		name = strings.TrimSpace(auth.Label)
	}
	if name == "" {
		_, account := auth.AccountInfo()
		name = strings.TrimSpace(account)
	}
	if name == "" {
		name = strings.TrimSpace(auth.ID)
	}
	accountType, account := auth.AccountInfo()
	index := auth.Index
	if index == "" {
		clone := auth.Clone()
		index = clone.EnsureIndex()
	}
	return CallerAuthOccupancy{
		AuthID:        strings.TrimSpace(auth.ID),
		AuthIndex:     strings.TrimSpace(index),
		Name:          name,
		Label:         strings.TrimSpace(auth.Label),
		Provider:      strings.TrimSpace(auth.Provider),
		AccountType:   strings.TrimSpace(accountType),
		Account:       strings.TrimSpace(account),
		Status:        auth.Status,
		StatusMessage: strings.TrimSpace(auth.StatusMessage),
		Disabled:      auth.Disabled,
		Unavailable:   auth.Unavailable,
		UpdatedAt:     auth.UpdatedAt,
	}
}
