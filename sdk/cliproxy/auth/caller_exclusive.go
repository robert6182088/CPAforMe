package auth

import (
	"context"
	"sort"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	log "github.com/sirupsen/logrus"
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

func callerExclusiveAuthClaimable(auth *Auth) bool {
	return callerExclusiveAuthEligible(auth) && auth != nil && !auth.Disabled && auth.Status != StatusDisabled
}

func (m *Manager) callerExclusiveAuthTTLDuration() time.Duration {
	if m == nil {
		return callerExclusiveAuthTTL
	}
	if ttl := time.Duration(m.callerExclusiveAuthTTL.Load()); ttl > 0 {
		return ttl
	}
	return callerExclusiveAuthTTL
}

func (m *Manager) callerExclusiveAuthStoreSnapshot() callerExclusiveOwnerStore {
	if m == nil {
		return nil
	}
	m.callerExclusiveAuthStoreMu.RLock()
	defer m.callerExclusiveAuthStoreMu.RUnlock()
	return m.callerExclusiveAuthStore
}

func (m *Manager) setCallerExclusiveAuthStore(store callerExclusiveOwnerStore) (previous callerExclusiveOwnerStore) {
	if m == nil {
		return nil
	}
	m.callerExclusiveAuthStoreMu.Lock()
	previous = m.callerExclusiveAuthStore
	m.callerExclusiveAuthStore = store
	m.callerExclusiveAuthStoreMu.Unlock()
	return previous
}

func (m *Manager) setCallerExclusiveAuthRuntimeConfig(cfg *internalconfig.CallerExclusiveAuthConfig) {
	if m == nil {
		return
	}
	ttl := callerExclusiveAuthTTL
	var nextStore callerExclusiveOwnerStore
	if cfg != nil {
		ttl = cfg.TTLDuration()
		if cfg.Redis.Enabled {
			store, errStore := newRedisCallerExclusiveOwnerStore(cfg.Redis)
			if errStore != nil {
				log.Warnf("failed to initialize caller exclusive auth redis store: %v", errStore)
			} else {
				nextStore = store
			}
		}
	}
	m.callerExclusiveAuthTTL.Store(ttl.Nanoseconds())
	previousStore := m.setCallerExclusiveAuthStore(nextStore)
	if previousStore != nil && previousStore != nextStore {
		if nextStore == nil {
			m.migrateCallerExclusiveOwnersFromStore(previousStore)
		}
		_ = previousStore.Close()
	}
	if nextStore == nil {
		return
	}
	m.migrateCallerExclusiveOwnersToStore(nextStore)
}

func (m *Manager) migrateCallerExclusiveOwnersToStore(store callerExclusiveOwnerStore) {
	if m == nil || store == nil {
		return
	}
	m.mu.RLock()
	records := make(map[string]callerExclusiveOwnerRecord, len(m.callerExclusiveAuthOwners))
	for resourceKey, record := range m.callerExclusiveAuthOwners {
		if strings.TrimSpace(record.Owner) == "" {
			continue
		}
		records[resourceKey] = record
	}
	m.mu.RUnlock()
	if len(records) == 0 {
		return
	}
	now := time.Now()
	ttl := m.callerExclusiveAuthTTLDuration()
	for resourceKey, record := range records {
		if record.ClaimedAt.IsZero() {
			record.ClaimedAt = now
		}
		_, _ = store.Claim(context.Background(), resourceKey, record.Owner, record, ttl)
	}
}

func (m *Manager) migrateCallerExclusiveOwnersFromStore(store callerExclusiveOwnerStore) {
	if m == nil || store == nil {
		return
	}
	snapshot, errSnapshot := store.Snapshot(context.Background(), nil)
	if errSnapshot != nil {
		log.Warnf("failed to snapshot caller exclusive auth store: %v", errSnapshot)
		return
	}
	m.mu.Lock()
	if len(snapshot) == 0 {
		if len(m.callerExclusiveAuthOwners) > 0 {
			clear(m.callerExclusiveAuthOwners)
		}
		m.mu.Unlock()
		return
	}
	if m.callerExclusiveAuthOwners == nil {
		m.callerExclusiveAuthOwners = make(map[string]callerExclusiveOwnerRecord, len(snapshot))
	}
	clear(m.callerExclusiveAuthOwners)
	for resourceKey, record := range snapshot {
		m.callerExclusiveAuthOwners[resourceKey] = record
	}
	m.mu.Unlock()
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
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		if err := store.Prune(context.Background(), m.callerExclusiveAuthTTLDuration()); err != nil {
			log.Warnf("failed to prune caller exclusive auth redis store: %v", err)
		}
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
	ttl := m.callerExclusiveAuthTTLDuration()
	for resourceKey, state := range m.callerExclusiveAuthOwners {
		if strings.TrimSpace(state.Owner) == "" || (!state.ClaimedAt.IsZero() && now.Sub(state.ClaimedAt) > ttl) {
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
	excluded := make([]string, 0)
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		m.mu.RLock()
		for _, auth := range m.auths {
			if !callerExclusiveAuthClaimable(auth) || strings.TrimSpace(auth.ID) == "" {
				continue
			}
			resourceKey := callerExclusiveAuthResourceKey(auth)
			if resourceKey == "" {
				continue
			}
			state, ok, errGet := store.Get(context.Background(), resourceKey)
			if errGet != nil {
				log.Warnf("failed to read caller exclusive auth redis store: %v", errGet)
				continue
			}
			if !ok {
				continue
			}
			owner := strings.TrimSpace(state.Owner)
			if owner == "" || owner == callerScope {
				continue
			}
			excluded = append(excluded, auth.ID)
		}
		m.mu.RUnlock()
	} else {
		m.mu.RLock()
		if len(m.callerExclusiveAuthOwners) == 0 {
			m.mu.RUnlock()
			return tried
		}
		for _, auth := range m.auths {
			if !callerExclusiveAuthClaimable(auth) || auth == nil || strings.TrimSpace(auth.ID) == "" {
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
	}

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
	if m == nil || !callerExclusiveAuthClaimable(auth) {
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
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		state, ok, errGet := store.Get(context.Background(), resourceKey)
		if errGet != nil {
			log.Warnf("failed to read caller exclusive auth redis store: %v", errGet)
			return true
		}
		if !ok {
			return true
		}
		owner := strings.TrimSpace(state.Owner)
		return owner == "" || owner == callerScope
	}
	owner := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey].Owner)
	return owner == "" || owner == callerScope
}

func (m *Manager) claimAuthForCaller(auth *Auth, opts cliproxyexecutor.Options) bool {
	if m == nil || !callerExclusiveAuthClaimable(auth) {
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
	now := time.Now()
	sequence := m.nextCallerExclusiveClaimSequence()
	record := callerExclusiveOwnerRecord{
		Owner:     callerScope,
		Sequence:  sequence,
		ClaimedAt: now,
	}
	ttl := m.callerExclusiveAuthTTLDuration()
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		if ok, errClaim := store.Claim(context.Background(), resourceKey, callerScope, record, ttl); errClaim != nil {
			log.Warnf("failed to claim caller exclusive auth in redis: %v", errClaim)
		} else if ok {
			return true
		} else {
			return false
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredCallerExclusiveOwnersLocked(now)
	if m.callerExclusiveAuthOwners == nil {
		m.callerExclusiveAuthOwners = make(map[string]callerExclusiveOwnerRecord)
	}
	if existing := strings.TrimSpace(m.callerExclusiveAuthOwners[resourceKey].Owner); existing == "" {
		m.callerExclusiveAuthOwners[resourceKey] = record
		return true
	} else if existing == callerScope {
		m.callerExclusiveAuthOwners[resourceKey] = record
		return true
	}
	return false
}

func (m *Manager) moveCallerExclusiveOwnerLocked(oldAuth, newAuth *Auth) {
	if m == nil || oldAuth == nil {
		return
	}
	oldKey := callerExclusiveAuthResourceKey(oldAuth)
	if !callerExclusiveAuthClaimable(newAuth) {
		m.deleteCallerExclusiveOwnerIfUnusedLocked(oldKey)
		return
	}
	newKey := callerExclusiveAuthResourceKey(newAuth)
	if oldKey == "" || oldKey == newKey {
		return
	}
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		state, ok, errGet := store.Get(context.Background(), oldKey)
		if errGet != nil {
			log.Warnf("failed to load caller exclusive auth from redis during move: %v", errGet)
			return
		}
		if !ok || strings.TrimSpace(state.Owner) == "" {
			return
		}
		if state.ClaimedAt.IsZero() {
			state.ClaimedAt = time.Now()
		}
		if newKey != "" {
			okClaim, errClaim := store.Claim(context.Background(), newKey, state.Owner, state, m.callerExclusiveAuthTTLDuration())
			if errClaim != nil {
				log.Warnf("failed to move caller exclusive auth in redis: %v", errClaim)
				return
			}
			if !okClaim {
				return
			}
		}
		if errDel := store.Delete(context.Background(), oldKey); errDel != nil {
			log.Warnf("failed to delete old caller exclusive auth from redis after move: %v", errDel)
		}
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
	if m == nil || resourceKey == "" {
		return
	}
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		for _, auth := range m.auths {
			if callerExclusiveAuthClaimable(auth) && callerExclusiveAuthResourceKey(auth) == resourceKey {
				return
			}
		}
		if err := store.Delete(context.Background(), resourceKey); err != nil {
			log.Warnf("failed to delete caller exclusive auth from redis: %v", err)
		}
		return
	}
	if len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	for _, auth := range m.auths {
		if callerExclusiveAuthClaimable(auth) && callerExclusiveAuthResourceKey(auth) == resourceKey {
			return
		}
	}
	delete(m.callerExclusiveAuthOwners, resourceKey)
}

func (m *Manager) pruneCallerExclusiveOwnersLocked() {
	if m == nil {
		return
	}
	activeKeys := make(map[string]struct{}, len(m.auths))
	for _, auth := range m.auths {
		if resourceKey := callerExclusiveAuthResourceKey(auth); resourceKey != "" && callerExclusiveAuthClaimable(auth) {
			activeKeys[resourceKey] = struct{}{}
		}
	}
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		if err := store.Prune(context.Background(), m.callerExclusiveAuthTTLDuration()); err != nil {
			log.Warnf("failed to prune caller exclusive auth redis store: %v", err)
		}
		snapshot, errSnapshot := store.Snapshot(context.Background(), nil)
		if errSnapshot != nil {
			log.Warnf("failed to load caller exclusive auth redis snapshot for pruning: %v", errSnapshot)
			return
		}
		for resourceKey := range snapshot {
			if _, ok := activeKeys[resourceKey]; ok {
				continue
			}
			if errDel := store.Delete(context.Background(), resourceKey); errDel != nil {
				log.Warnf("failed to delete inactive caller exclusive auth from redis: %v", errDel)
			}
		}
		return
	}
	if len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	m.pruneExpiredCallerExclusiveOwnersLocked(time.Now())
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
	activeKeys := make(map[string]struct{}, len(m.auths))
	for _, auth := range m.auths {
		if resourceKey := callerExclusiveAuthResourceKey(auth); resourceKey != "" && callerExclusiveAuthClaimable(auth) {
			activeKeys[resourceKey] = struct{}{}
		}
	}
	if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
		snapshot, errSnapshot := store.Snapshot(context.Background(), nil)
		if errSnapshot != nil {
			log.Warnf("failed to load caller exclusive auth snapshot for config update: %v", errSnapshot)
			return
		}
		if len(snapshot) == 0 {
			return
		}
		if len(enabledScopes) == 0 {
			for resourceKey := range snapshot {
				if errDel := store.Delete(context.Background(), resourceKey); errDel != nil {
					log.Warnf("failed to delete caller exclusive auth during config update: %v", errDel)
				}
			}
			clear(m.callerExclusiveAuthOwners)
			return
		}
		clear(m.callerExclusiveAuthOwners)
		for resourceKey, record := range snapshot {
			_, ownerEnabled := enabledScopes[strings.TrimSpace(record.Owner)]
			_, authActive := activeKeys[resourceKey]
			if ownerEnabled && authActive {
				m.callerExclusiveAuthOwners[resourceKey] = record
				continue
			}
			if errDel := store.Delete(context.Background(), resourceKey); errDel != nil {
				log.Warnf("failed to delete caller exclusive auth during config update: %v", errDel)
			}
		}
		return
	}
	if len(m.callerExclusiveAuthOwners) == 0 {
		return
	}
	m.pruneExpiredCallerExclusiveOwnersLocked(time.Now())
	if len(enabledScopes) == 0 {
		clear(m.callerExclusiveAuthOwners)
		return
	}
	for resourceKey, state := range m.callerExclusiveAuthOwners {
		_, ownerEnabled := enabledScopes[strings.TrimSpace(state.Owner)]
		_, authActive := activeKeys[resourceKey]
		if !ownerEnabled || !authActive {
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
		var state callerExclusiveOwnerRecord
		if store := m.callerExclusiveAuthStoreSnapshot(); store != nil {
			state, _, _ = store.Get(context.Background(), resourceKey)
		} else {
			state = m.callerExclusiveAuthOwners[resourceKey]
		}
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
