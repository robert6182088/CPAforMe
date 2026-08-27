package auth

import (
	"sort"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
)

type callerExclusiveOwnerRecord struct {
	Owner     string
	Sequence  uint64
	ClaimedAt time.Time
}

const callerExclusiveAuthTTL = 72 * time.Hour

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
	ClaimSequence uint64    `json:"claim_sequence,omitempty"`
	ClaimedAt     time.Time `json:"claimed_at,omitempty"`
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

func (m *Manager) nextCallerExclusiveClaimSequence() uint64 {
	if m == nil {
		return 0
	}
	return m.callerExclusiveAuthSeq.Add(1)
}

func (m *Manager) pruneExpiredCallerExclusiveOwners(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredCallerExclusiveOwnersLocked(now)
}

func (m *Manager) pruneExpiredCallerExclusiveOwnersLocked(now time.Time) {
	if m == nil || len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	for resourceKey, state := range m.callerExclusiveAuthOwners {
		if strings.TrimSpace(state.Owner) == "" || (!state.ClaimedAt.IsZero() && now.Sub(state.ClaimedAt) > callerExclusiveAuthTTL) {
			delete(m.callerExclusiveAuthOwners, resourceKey)
		}
	}
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
	m.pruneExpiredCallerExclusiveOwners(time.Now())
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
		owner := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey].Owner)
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
	owner := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey].Owner)
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
	now := time.Now()
	m.pruneExpiredCallerExclusiveOwnersLocked(now)
	if m.callerExclusiveAuthOwners == nil {
		m.callerExclusiveAuthOwners = make(map[string]callerExclusiveOwnerRecord)
	}
	if existing := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey].Owner); existing == "" {
		m.callerExclusiveAuthOwners[resourceKey] = callerExclusiveOwnerRecord{
			Owner:     callerScope,
			Sequence:  m.nextCallerExclusiveClaimSequence(),
			ClaimedAt: now,
		}
		return true
	} else if existing != callerScope {
		return false
	}
	m.callerExclusiveAuthOwners[resourceKey] = callerExclusiveOwnerRecord{
		Owner:     callerScope,
		Sequence:  m.nextCallerExclusiveClaimSequence(),
		ClaimedAt: now,
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
	state := m.callerExclusiveAuthOwners[oldKey]
	owner := strings.TrimSpace(state.Owner)
	if owner != "" && newKey != "" && strings.TrimSpace(m.callerExclusiveAuthOwners[newKey].Owner) == "" {
		m.callerExclusiveAuthOwners[newKey] = state
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
	m.pruneExpiredCallerExclusiveOwnersLocked(time.Now())
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
	m.pruneExpiredCallerExclusiveOwnersLocked(time.Now())
	if len(enabledScopes) == 0 {
		clear(m.callerExclusiveAuthOwners)
		return
	}
	for resourceKey, state := range m.callerExclusiveAuthOwners {
		if _, ok := enabledScopes[strings.TrimSpace(state.Owner)]; !ok {
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

	m.mu.Lock()
	m.pruneExpiredCallerExclusiveOwnersLocked(time.Now())
	defer m.mu.Unlock()
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		resourceKey := callerExclusiveAuthResourceKey(auth)
		if resourceKey == "" {
			continue
		}
		state := m.callerExclusiveAuthOwners[resourceKey]
		owner := strings.TrimSpace(state.Owner)
		if _, ok := allowed[owner]; !ok {
			continue
		}
		result[owner] = append(result[owner], callerAuthOccupancyFromAuth(auth, state.Sequence, state.ClaimedAt))
	}
	for scope := range result {
		sort.Slice(result[scope], func(i, j int) bool {
			if result[scope][i].ClaimSequence != result[scope][j].ClaimSequence {
				return result[scope][i].ClaimSequence > result[scope][j].ClaimSequence
			}
			left := strings.ToLower(result[scope][i].Provider + "|" + result[scope][i].Name + "|" + result[scope][i].AuthID)
			right := strings.ToLower(result[scope][j].Provider + "|" + result[scope][j].Name + "|" + result[scope][j].AuthID)
			return left < right
		})
	}
	return result
}

func callerAuthOccupancyFromAuth(auth *Auth, sequence uint64, claimedAt time.Time) CallerAuthOccupancy {
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
		ClaimSequence: sequence,
		ClaimedAt:     claimedAt,
		UpdatedAt:     auth.UpdatedAt,
	}
}
