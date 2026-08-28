package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var lastRefreshKeys = []string{"last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"}

var (
	callbackForwardersMu  sync.Mutex
	callbackForwarders    = make(map[int]*callbackForwarder)
	authFileEntryMu       sync.Mutex
	errAuthFileMustBeJSON = errors.New("auth file must be .json")
	errAuthFileNotFound   = errors.New("auth file not found")
	errPluginVirtualAuth  = errors.New("plugin virtual auth cannot be modified directly; edit or delete the source auth file")
	newCodexOAuthService  = func(cfg *config.Config) codexOAuthService { return codex.NewCodexAuth(cfg) }
)

type authFileListOptions struct {
	Name           string
	AuthIndex      string
	Status         string
	ExpiredDate    string
	HasExpiredDate bool
	Limit          int
	Offset         int
	HasLimit       bool
}

func extractLastRefreshTimestamp(meta map[string]any) (time.Time, bool) {
	if len(meta) == 0 {
		return time.Time{}, false
	}
	for _, key := range lastRefreshKeys {
		if val, ok := meta[key]; ok {
			if ts, ok1 := parseLastRefreshValue(val); ok1 {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

func parseLastRefreshValue(v any) (time.Time, bool) {
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return time.Time{}, false
		}
		layouts := []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05Z07:00"}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts.UTC(), true
			}
		}
		if unix, err := strconv.ParseInt(s, 10, 64); err == nil && unix > 0 {
			return time.Unix(unix, 0).UTC(), true
		}
	case float64:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(val), 0).UTC(), true
	case int64:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(val, 0).UTC(), true
	case int:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(val), 0).UTC(), true
	case json.Number:
		if i, err := val.Int64(); err == nil && i > 0 {
			return time.Unix(i, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

func parseAuthFileListOptions(c *gin.Context) (authFileListOptions, error) {
	opts := authFileListOptions{
		Name:      strings.TrimSpace(c.Query("name")),
		AuthIndex: strings.TrimSpace(c.Query("auth_index")),
		Status:    normalizeAuthFileStatusFilter(c.Query("status")),
	}
	expiredDate, hasExpiredDate, errExpiredDate := parseAuthFileListDate(c.Query("expired_date"))
	if errExpiredDate != nil {
		return opts, fmt.Errorf("expired_date is invalid")
	}
	opts.ExpiredDate = expiredDate
	opts.HasExpiredDate = hasExpiredDate
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			return opts, fmt.Errorf("limit must be a positive integer")
		}
		if limit > 1000 {
			limit = 1000
		}
		opts.Limit = limit
		opts.HasLimit = true
	}
	if raw := strings.TrimSpace(c.Query("offset")); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return opts, fmt.Errorf("offset must be a non-negative integer")
		}
		opts.Offset = offset
	}
	return opts, nil
}

func parseAuthFileListDate(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, nil
	}
	if len(raw) != len("2006-01-02") {
		return "", false, fmt.Errorf("invalid date")
	}
	parsed, errParse := time.ParseInLocation("2006-01-02", raw, time.Local)
	if errParse != nil {
		return "", false, errParse
	}
	return parsed.Format("2006-01-02"), true, nil
}

func parseAuthFileListTime(raw string, endOfDay bool) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false, nil
	}
	if unix, err := strconv.ParseInt(raw, 10, 64); err == nil && unix > 0 {
		if unix < 1_000_000_000_000 {
			return time.Unix(unix, 0), true, nil
		}
		return time.UnixMilli(unix), true, nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	var parsed time.Time
	var err error
	for _, layout := range layouts {
		if layout == "2006-01-02" {
			parsed, err = time.ParseInLocation(layout, raw, time.Local)
		} else {
			parsed, err = time.Parse(layout, raw)
			if err != nil {
				parsed, err = time.ParseInLocation(layout, raw, time.Local)
			}
		}
		if err == nil {
			if layout == "2006-01-02" && endOfDay {
				parsed = parsed.Add(24*time.Hour - time.Nanosecond)
			}
			return parsed, true, nil
		}
	}
	return time.Time{}, false, fmt.Errorf("invalid time")
}

func normalizeAuthFileStatusFilter(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "", "all", "*":
		return ""
	case "enabled", "active":
		return "enabled"
	case "disabled", "inactive":
		return "disabled"
	case "problem", "error", "unavailable":
		return "problem"
	default:
		return status
	}
}

func matchesAuthFileStatus(disabled bool, status string, unavailable bool, statusMessage string, filter string) bool {
	filter = normalizeAuthFileStatusFilter(filter)
	if filter == "" {
		return true
	}
	status = strings.ToLower(strings.TrimSpace(status))
	statusMessage = strings.ToLower(strings.TrimSpace(statusMessage))
	problem := !disabled && (unavailable || status == "error" || (statusMessage != "" && statusMessage != "ok" && statusMessage != "healthy" && statusMessage != "ready" && statusMessage != "success" && statusMessage != "available"))
	switch filter {
	case "enabled":
		return !disabled
	case "disabled":
		return disabled || status == "disabled"
	case "problem":
		return problem
	default:
		return status == filter
	}
}

func matchesAuthFileEntryOptions(entry gin.H, opts authFileListOptions) bool {
	if entry == nil {
		return false
	}
	disabled, _ := entry["disabled"].(bool)
	status, _ := entry["status"].(string)
	unavailable, _ := entry["unavailable"].(bool)
	statusMessage, _ := entry["status_message"].(string)
	if !matchesAuthFileStatus(disabled, status, unavailable, statusMessage, opts.Status) {
		return false
	}
	if opts.HasExpiredDate && authFileEntryExpiredDate(entry) != opts.ExpiredDate {
		return false
	}
	return true
}

func authFileEntryExpiredDate(entry gin.H) string {
	for _, key := range []string{"expired", "expire", "expires_at", "expiresAt", "expiry", "expires"} {
		if value, ok := entry[key]; ok {
			if date := authFileDatePart(value); date != "" {
				return date
			}
		}
	}
	return ""
}

func paginateAuths(auths []*coreauth.Auth, opts authFileListOptions) []*coreauth.Auth {
	if opts.Offset >= len(auths) {
		return nil
	}
	start := opts.Offset
	end := len(auths)
	if opts.HasLimit && start+opts.Limit < end {
		end = start + opts.Limit
	}
	return auths[start:end]
}

func authFileListOffsetAllowed(index int, opts authFileListOptions) bool {
	return index >= opts.Offset
}

func authFileListResponse(files []gin.H, total int, opts authFileListOptions) gin.H {
	resp := gin.H{
		"files":  files,
		"total":  total,
		"offset": opts.Offset,
	}
	if opts.HasLimit {
		resp["limit"] = opts.Limit
		nextOffset := opts.Offset + len(files)
		hasMore := nextOffset < total
		resp["has_more"] = hasMore
		if hasMore {
			resp["next_offset"] = nextOffset
		}
	} else {
		resp["limit"] = 0
		resp["has_more"] = false
	}
	return resp
}

func (h *Handler) ListAuthFiles(c *gin.Context) {
	if h == nil {
		c.JSON(500, gin.H{"error": "handler not initialized"})
		return
	}
	opts, errOptions := parseAuthFileListOptions(c)
	if errOptions != nil {
		c.JSON(400, gin.H{"error": errOptions.Error()})
		return
	}
	if h.authManager == nil {
		h.listAuthFilesFromDisk(c, opts)
		return
	}
	auths := h.authManager.List()
	filtered := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if !matchesAuthFileListOptions(auth, opts) {
			continue
		}
		filtered = append(filtered, auth)
	}
	sort.Slice(filtered, func(i, j int) bool {
		nameI := authListName(filtered[i])
		nameJ := authListName(filtered[j])
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})
	total := len(filtered)
	filtered = paginateAuths(filtered, opts)
	files := make([]gin.H, 0, len(filtered))
	for _, auth := range filtered {
		if entry := h.buildAuthFileEntry(auth); entry != nil {
			files = append(files, entry)
		}
	}
	c.JSON(200, authFileListResponse(files, total, opts))
}

func lockedAuthIndex(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	authFileEntryMu.Lock()
	defer authFileEntryMu.Unlock()
	return strings.TrimSpace(auth.EnsureIndex())
}

func matchesAuthFileLookup(auth *coreauth.Auth, name string, authIndex string) bool {
	if auth == nil {
		return false
	}
	if name != "" && strings.TrimSpace(auth.ID) != name && strings.TrimSpace(auth.FileName) != name {
		return false
	}
	if authIndex != "" && lockedAuthIndex(auth) != authIndex {
		return false
	}
	return true
}

func matchesAuthFileListOptions(auth *coreauth.Auth, opts authFileListOptions) bool {
	if !matchesAuthFileLookup(auth, opts.Name, opts.AuthIndex) {
		return false
	}
	disabled, status, unavailable, statusMessage := authDisabledStatus(auth)
	if !matchesAuthFileStatus(disabled, status, unavailable, statusMessage, opts.Status) {
		return false
	}
	if opts.HasExpiredDate && authExpiredDate(auth) != opts.ExpiredDate {
		return false
	}
	return true
}

func authListName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

func authDisabledStatus(auth *coreauth.Auth) (disabled bool, status string, unavailable bool, statusMessage string) {
	if auth == nil {
		return false, "", false, ""
	}
	return auth.Disabled, strings.TrimSpace(string(auth.Status)), auth.Unavailable, strings.TrimSpace(auth.StatusMessage)
}

func authExpiredDate(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		for _, key := range []string{"expired", "expire", "expires_at", "expiresAt", "expiry", "expires"} {
			if value, ok := auth.Metadata[key]; ok {
				if date := authFileDatePart(value); date != "" {
					return date
				}
			}
		}
	}
	if ts, ok := auth.ExpirationTime(); ok && !ts.IsZero() {
		return ts.In(time.Local).Format("2006-01-02")
	}
	return ""
}

func authFileDatePart(value any) string {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if len(trimmed) >= len("2006-01-02") {
			candidate := trimmed[:len("2006-01-02")]
			if _, errParse := time.ParseInLocation("2006-01-02", candidate, time.Local); errParse == nil {
				return candidate
			}
		}
		if parsed, ok, _ := parseAuthFileListTime(trimmed, false); ok {
			return parsed.In(time.Local).Format("2006-01-02")
		}
	case time.Time:
		if !typed.IsZero() {
			return typed.In(time.Local).Format("2006-01-02")
		}
	case int64:
		if typed > 0 {
			return normalizeAuthFileUnix(typed).In(time.Local).Format("2006-01-02")
		}
	case int:
		if typed > 0 {
			return normalizeAuthFileUnix(int64(typed)).In(time.Local).Format("2006-01-02")
		}
	case float64:
		if typed > 0 {
			return normalizeAuthFileUnix(int64(typed)).In(time.Local).Format("2006-01-02")
		}
	case json.Number:
		if parsed, errParse := typed.Int64(); errParse == nil && parsed > 0 {
			return normalizeAuthFileUnix(parsed).In(time.Local).Format("2006-01-02")
		}
	}
	return ""
}

func normalizeAuthFileUnix(raw int64) time.Time {
	if raw > 1_000_000_000_000 {
		return time.UnixMilli(raw)
	}
	return time.Unix(raw, 0)
}

func (h *Handler) lookupAuthFile(name string, authIndex string) (*coreauth.Auth, bool) {
	name = strings.TrimSpace(name)
	authIndex = strings.TrimSpace(authIndex)
	if h == nil || h.authManager == nil || name == "" {
		return nil, false
	}
	if authIndex == "" {
		if auth, ok := h.authManager.GetByID(name); ok {
			return auth, true
		}
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth != nil && strings.TrimSpace(auth.FileName) == name {
				return auth, true
			}
		}
		return nil, false
	}
	auths := h.authManager.List()
	for _, auth := range auths {
		if matchesAuthFileLookup(auth, name, authIndex) {
			return auth, true
		}
	}
	return nil, false
}

// GetAuthFileModels returns the models supported by a specific auth file
func (h *Handler) GetAuthFileModels(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}

	// Try to find auth ID via authManager
	var authID string
	if h.authManager != nil {
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth.FileName == name || auth.ID == name {
				authID = auth.ID
				break
			}
		}
	}

	if authID == "" {
		authID = name // fallback to filename as ID
	}

	// Get models from registry
	reg := registry.GetGlobalRegistry()
	models := reg.GetModelsForClient(authID)

	result := make([]gin.H, 0, len(models))
	for _, m := range models {
		entry := gin.H{
			"id": m.ID,
		}
		if m.DisplayName != "" {
			entry["display_name"] = m.DisplayName
		}
		if m.Type != "" {
			entry["type"] = m.Type
		}
		if m.OwnedBy != "" {
			entry["owned_by"] = m.OwnedBy
		}
		result = append(result, entry)
	}

	c.JSON(200, gin.H{"models": result})
}

// List auth files from disk when the auth manager is unavailable.
func (h *Handler) listAuthFilesFromDisk(c *gin.Context, opts authFileListOptions) {
	entries, err := os.ReadDir(h.cfg.AuthDir)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("failed to read auth dir: %v", err)})
		return
	}
	files := make([]gin.H, 0)
	if opts.AuthIndex != "" {
		c.JSON(200, authFileListResponse(files, 0, opts))
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	total := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if opts.Name != "" && name != opts.Name {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if info, errInfo := e.Info(); errInfo == nil {
			fileData := gin.H{"name": name, "size": info.Size(), "modtime": info.ModTime()}

			// Read file to get type field
			full := filepath.Join(h.cfg.AuthDir, name)
			if data, errRead := os.ReadFile(full); errRead == nil {
				typeValue := gjson.GetBytes(data, "type").String()
				emailValue := gjson.GetBytes(data, "email").String()
				fileData["type"] = typeValue
				fileData["email"] = emailValue
				if expired := strings.TrimSpace(gjson.GetBytes(data, "expired").String()); expired != "" {
					fileData["expired"] = expired
				}
				if projectID := strings.TrimSpace(gjson.GetBytes(data, "project_id").String()); projectID != "" {
					fileData["project_id"] = projectID
				}
				if pv := gjson.GetBytes(data, "priority"); pv.Exists() {
					switch pv.Type {
					case gjson.Number:
						fileData["priority"] = int(pv.Int())
					case gjson.String:
						if parsed, errAtoi := strconv.Atoi(strings.TrimSpace(pv.String())); errAtoi == nil {
							fileData["priority"] = parsed
						}
					}
				}
				if wv := gjson.GetBytes(data, coreauth.AttributeWeight); wv.Exists() {
					var rawWeight string
					switch wv.Type {
					case gjson.Number:
						rawWeight = wv.Raw
					case gjson.String:
						rawWeight = wv.String()
					}
					if rawWeight != "" {
						if weight, errWeight := credentialweight.ParseString(rawWeight); errWeight == nil {
							fileData[coreauth.AttributeWeight] = weight
						}
					}
				}
				if nv := gjson.GetBytes(data, "note"); nv.Exists() && nv.Type == gjson.String {
					if trimmed := strings.TrimSpace(nv.String()); trimmed != "" {
						fileData["note"] = trimmed
					}
				}
				if wv := gjson.GetBytes(data, "websockets"); wv.Exists() {
					switch wv.Type {
					case gjson.True:
						fileData["websockets"] = true
					case gjson.False:
						fileData["websockets"] = false
					case gjson.String:
						if parsed, errParse := strconv.ParseBool(strings.TrimSpace(wv.String())); errParse == nil {
							fileData["websockets"] = parsed
						}
					}
				}
				if requestRetry, okRetry := authFileRequestRetryFromJSON(data); okRetry {
					fileData["request_retry"] = requestRetry
				}
			}

			if !matchesAuthFileEntryOptions(fileData, opts) {
				continue
			}
			total++
			if !authFileListOffsetAllowed(total-1, opts) {
				continue
			}
			if opts.HasLimit && len(files) >= opts.Limit {
				continue
			}
			files = append(files, fileData)
		}
	}
	c.JSON(200, authFileListResponse(files, total, opts))
}

func (h *Handler) buildAuthFileEntry(auth *coreauth.Auth) gin.H {
	authFileEntryMu.Lock()
	defer authFileEntryMu.Unlock()
	return h.buildAuthFileEntryLocked(auth)
}

func (h *Handler) buildAuthFileEntryLocked(auth *coreauth.Auth) gin.H {
	if auth == nil {
		return nil
	}
	auth.EnsureIndex()
	runtimeOnly := isRuntimeOnlyAuth(auth)
	if runtimeOnly && (auth.Disabled || auth.Status == coreauth.StatusDisabled) {
		return nil
	}
	path := strings.TrimSpace(authAttribute(auth, "path"))
	if path == "" && !runtimeOnly {
		return nil
	}
	name := strings.TrimSpace(auth.FileName)
	if name == "" {
		name = auth.ID
	}
	entry := gin.H{
		"id":             auth.ID,
		"auth_index":     auth.Index,
		"name":           name,
		"type":           strings.TrimSpace(auth.Provider),
		"provider":       strings.TrimSpace(auth.Provider),
		"label":          auth.Label,
		"status":         auth.Status,
		"status_message": auth.StatusMessage,
		"disabled":       auth.Disabled,
		"unavailable":    auth.Unavailable,
		"runtime_only":   runtimeOnly,
		"source":         "memory",
		"size":           int64(0),
	}
	entry["success"] = auth.Success
	entry["failed"] = auth.Failed
	entry["recent_requests"] = auth.RecentRequestsSnapshot(time.Now())
	entry["quota"] = quotaObservationPayloadForProvider(auth.Provider, auth.Quota)
	if modelQuotas := modelQuotaObservationPayload(auth.Provider, auth.ModelStates); len(modelQuotas) > 0 {
		entry["model_quotas"] = modelQuotas
	}
	if email := authEmail(auth); email != "" {
		entry["email"] = email
	}
	if projectID := authProjectID(auth); projectID != "" {
		entry["project_id"] = projectID
	}
	if accountType, account := auth.AccountInfo(); accountType != "" || account != "" {
		if accountType != "" {
			entry["account_type"] = accountType
		}
		if account != "" {
			entry["account"] = account
		}
	}
	if !auth.CreatedAt.IsZero() {
		entry["created_at"] = auth.CreatedAt
	}
	if !auth.UpdatedAt.IsZero() {
		entry["modtime"] = auth.UpdatedAt
		entry["updated_at"] = auth.UpdatedAt
	}
	if !auth.LastRefreshedAt.IsZero() {
		entry["last_refresh"] = auth.LastRefreshedAt
	}
	if !auth.NextRetryAfter.IsZero() {
		entry["next_retry_after"] = auth.NextRetryAfter
	}
	if expired := authExpiredValue(auth); expired != "" {
		entry["expired"] = expired
	}
	if path != "" {
		entry["path"] = path
		entry["source"] = "file"
		if info, err := os.Stat(path); err == nil {
			entry["size"] = info.Size()
			entry["modtime"] = info.ModTime()
		} else if os.IsNotExist(err) {
			// Hide credentials removed from disk but still lingering in memory.
			if !runtimeOnly && (auth.Disabled || auth.Status == coreauth.StatusDisabled || strings.EqualFold(strings.TrimSpace(auth.StatusMessage), "removed via management api")) {
				return nil
			}
			entry["source"] = "memory"
		} else {
			log.WithError(err).Warnf("failed to stat auth file %s", path)
		}
	}
	if claims := extractCodexIDTokenClaims(auth); claims != nil {
		entry["id_token"] = claims
	}
	// Expose priority from Attributes (set by synthesizer from JSON "priority" field).
	// Fall back to Metadata for auths registered via UploadAuthFile (no synthesizer).
	if p := strings.TrimSpace(authAttribute(auth, "priority")); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			entry["priority"] = parsed
		}
	} else if auth.Metadata != nil {
		if rawPriority, ok := auth.Metadata["priority"]; ok {
			switch v := rawPriority.(type) {
			case float64:
				entry["priority"] = int(v)
			case int:
				entry["priority"] = v
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					entry["priority"] = parsed
				}
			}
		}
	}
	// Expose note from Attributes (set by synthesizer from JSON "note" field).
	// Fall back to Metadata for auths registered via UploadAuthFile (no synthesizer).
	if note := strings.TrimSpace(authAttribute(auth, "note")); note != "" {
		entry["note"] = note
	} else if auth.Metadata != nil {
		if rawNote, ok := auth.Metadata["note"].(string); ok {
			if trimmed := strings.TrimSpace(rawNote); trimmed != "" {
				entry["note"] = trimmed
			}
		}
	}
	if weight, ok := authWeightValue(auth); ok {
		entry[coreauth.AttributeWeight] = weight
	}
	if websockets, ok := authWebsocketsValue(auth); ok {
		entry["websockets"] = websockets
	}
	if requestRetry, ok := auth.RequestRetryOverride(); ok {
		entry["request_retry"] = requestRetry
	}
	return entry
}

func authExpiredValue(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		for _, key := range []string{"expired", "expire", "expires_at", "expiresAt", "expiry", "expires"} {
			if value, ok := auth.Metadata[key]; ok {
				switch typed := value.(type) {
				case string:
					if trimmed := strings.TrimSpace(typed); trimmed != "" {
						return trimmed
					}
				case json.Number:
					if trimmed := strings.TrimSpace(typed.String()); trimmed != "" {
						return trimmed
					}
				case float64:
					if typed > 0 {
						return normalizeAuthFileUnix(int64(typed)).Format(time.RFC3339)
					}
				case int64:
					if typed > 0 {
						return normalizeAuthFileUnix(typed).Format(time.RFC3339)
					}
				case int:
					if typed > 0 {
						return normalizeAuthFileUnix(int64(typed)).Format(time.RFC3339)
					}
				}
			}
		}
	}
	if ts, ok := auth.ExpirationTime(); ok && !ts.IsZero() {
		return ts.Format(time.RFC3339)
	}
	return ""
}

func authFileRequestRetryFromJSON(data []byte) (int, bool) {
	var metadata map[string]any
	if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
		return 0, false
	}
	return (&coreauth.Auth{Metadata: metadata}).RequestRetryOverride()
}

// quotaObservationPayload exposes only passive provider observations. Cooldown
// fields are intentionally excluded so this management response cannot be
// mistaken for scheduler state or influence scheduling behavior.
func quotaObservationPayloadForProvider(provider string, quota coreauth.QuotaState) gin.H {
	if !coreauth.ProviderSupportsQuotaObservation(provider) {
		return quotaObservationPayload(coreauth.QuotaState{})
	}
	return quotaObservationPayload(quota)
}

func quotaObservationPayload(quota coreauth.QuotaState) gin.H {
	observed := gin.H{}
	if !quota.ObservedAt.IsZero() {
		observed["observed_at"] = quota.ObservedAt
	}
	signals := make(map[string]string, len(quota.Signals))
	for key, value := range quota.Signals {
		signals[key] = value
	}
	observed["signals"] = signals
	return observed
}

func modelQuotaObservationPayload(provider string, states map[string]*coreauth.ModelState) gin.H {
	if !coreauth.ProviderSupportsQuotaObservation(provider) {
		return gin.H{}
	}
	observations := gin.H{}
	for model, state := range states {
		if state == nil {
			continue
		}
		if state.Quota.ObservedAt.IsZero() && len(state.Quota.Signals) == 0 {
			continue
		}
		observations[model] = quotaObservationPayloadForProvider(provider, state.Quota)
	}
	return observations
}

func authWeightValue(auth *coreauth.Auth) (int64, bool) {
	if auth == nil {
		return 0, false
	}
	if rawWeight := strings.TrimSpace(authAttribute(auth, coreauth.AttributeWeight)); rawWeight != "" {
		weight, errWeight := credentialweight.ParseString(rawWeight)
		return weight, errWeight == nil
	}
	if auth.Metadata == nil {
		return 0, false
	}
	rawWeight, ok := auth.Metadata[coreauth.AttributeWeight]
	if !ok || rawWeight == nil {
		return 0, false
	}
	weight, errWeight := credentialweight.ParseValue(rawWeight)
	return weight, errWeight == nil
}

func authWebsocketsValue(auth *coreauth.Auth) (bool, bool) {
	if auth == nil {
		return false, false
	}
	if auth.Attributes != nil {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed, true
			}
		}
	}
	if auth.Metadata == nil {
		return false, false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed, true
		}
	}
	return false, false
}

func authProjectID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["project_id"].(string); ok {
			if projectID := strings.TrimSpace(v); projectID != "" {
				return projectID
			}
		}
	}
	if auth.Attributes != nil {
		if projectID := strings.TrimSpace(auth.Attributes["project_id"]); projectID != "" {
			return projectID
		}
	}
	return ""
}

func extractCodexIDTokenClaims(auth *coreauth.Auth) gin.H {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil
	}
	idTokenRaw, ok := auth.Metadata["id_token"].(string)
	if !ok {
		return nil
	}
	idToken := strings.TrimSpace(idTokenRaw)
	if idToken == "" {
		return nil
	}
	claims, err := codex.ParseJWTToken(idToken)
	if err != nil || claims == nil {
		return nil
	}

	result := gin.H{}
	if v := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID); v != "" {
		result["chatgpt_account_id"] = v
	}
	if v := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); v != "" {
		result["plan_type"] = v
	}
	if v := claims.CodexAuthInfo.ChatgptSubscriptionActiveStart; v != nil {
		result["chatgpt_subscription_active_start"] = v
	}
	if v := claims.CodexAuthInfo.ChatgptSubscriptionActiveUntil; v != nil {
		result["chatgpt_subscription_active_until"] = v
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func authEmail(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["email"].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["email"]); v != "" {
			return v
		}
		if v := strings.TrimSpace(auth.Attributes["account_email"]); v != "" {
			return v
		}
	}
	return ""
}

func authAttribute(auth *coreauth.Auth, key string) string {
	if auth == nil || len(auth.Attributes) == 0 {
		return ""
	}
	return auth.Attributes[key]
}

func isRuntimeOnlyAuth(auth *coreauth.Auth) bool {
	if auth == nil || len(auth.Attributes) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true")
}

func isUnsafeAuthFileName(name string) bool {
	if strings.TrimSpace(name) == "" {
		return true
	}
	if strings.ContainsAny(name, "/\\") {
		return true
	}
	if filepath.VolumeName(name) != "" {
		return true
	}
	return false
}
