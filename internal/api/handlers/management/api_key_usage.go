package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coresession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
)

type apiKeyUsageEntry struct {
	Success        int64                          `json:"success"`
	Failed         int64                          `json:"failed"`
	RecentRequests []coreauth.RecentRequestBucket `json:"recent_requests"`
}

type apiKeyAuthOccupancyEntry struct {
	APIKey      string                         `json:"api-key"`
	Alias       string                         `json:"alias,omitempty"`
	Credentials []coreauth.CallerAuthOccupancy `json:"credentials"`
}

func mergeRecentRequestBuckets(dst, src []coreauth.RecentRequestBucket) []coreauth.RecentRequestBucket {
	if len(dst) == 0 {
		return src
	}
	if len(src) == 0 {
		return dst
	}
	if len(dst) != len(src) {
		n := len(dst)
		if len(src) < n {
			n = len(src)
		}
		for i := 0; i < n; i++ {
			dst[i].Success += src[i].Success
			dst[i].Failed += src[i].Failed
		}
		return dst
	}
	for i := range dst {
		dst[i].Success += src[i].Success
		dst[i].Failed += src[i].Failed
	}
	return dst
}

func apiKeyUsageProviderKey(auth *coreauth.Auth) string {
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if auth.Attributes != nil {
		if compatName := strings.TrimSpace(auth.Attributes["compat_name"]); compatName != "" {
			provider = strings.ToLower(compatName)
		}
	}
	if provider == "" {
		return "unknown"
	}
	return provider
}

// GetAPIKeyUsage returns recent request buckets for all in-memory api_key auths,
// grouped by provider and keyed by "base_url|api_key".
func (h *Handler) GetAPIKeyUsage(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}

	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	now := time.Now()
	out := make(map[string]map[string]apiKeyUsageEntry)
	for _, auth := range manager.List() {
		if auth == nil {
			continue
		}
		kind, apiKey := auth.AccountInfo()
		if !strings.EqualFold(strings.TrimSpace(kind), "api_key") {
			continue
		}
		apiKey = strings.TrimSpace(apiKey)
		if apiKey == "" {
			continue
		}
		baseURL := ""
		if auth.Attributes != nil {
			baseURL = strings.TrimSpace(auth.Attributes["base_url"])
			if baseURL == "" {
				baseURL = strings.TrimSpace(auth.Attributes["base-url"])
			}
		}
		compositeKey := baseURL + "|" + apiKey
		provider := apiKeyUsageProviderKey(auth)

		recent := auth.RecentRequestsSnapshot(now)
		providerBucket, ok := out[provider]
		if !ok {
			providerBucket = make(map[string]apiKeyUsageEntry)
			out[provider] = providerBucket
		}
		if existing, exists := providerBucket[compositeKey]; exists {
			existing.Success += auth.Success
			existing.Failed += auth.Failed
			existing.RecentRequests = mergeRecentRequestBuckets(existing.RecentRequests, recent)
			providerBucket[compositeKey] = existing
			continue
		}
		providerBucket[compositeKey] = apiKeyUsageEntry{
			Success:        auth.Success,
			Failed:         auth.Failed,
			RecentRequests: recent,
		}
	}

	c.JSON(http.StatusOK, out)
}

// GetAPIKeyAuthOccupancy returns auth file credentials claimed by enabled downstream API keys.
func (h *Handler) GetAPIKeyAuthOccupancy(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}

	h.mu.Lock()
	cfg := h.cfg
	manager := h.authManager
	var entries []config.APIKeyEntry
	if cfg != nil {
		entries = cfg.AccessAPIKeyEntries()
	}
	h.mu.Unlock()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	type itemWithScope struct {
		scope string
		item  apiKeyAuthOccupancyEntry
	}
	items := make([]itemWithScope, 0, len(entries))
	scopes := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Disabled {
			continue
		}
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		scope := coresession.CallerScope(key)
		if scope == "" {
			continue
		}
		scopes = append(scopes, scope)
		items = append(items, itemWithScope{
			scope: scope,
			item: apiKeyAuthOccupancyEntry{
				APIKey: util.HideAPIKey(key),
				Alias:  strings.TrimSpace(entry.Alias),
			},
		})
	}

	occupancy := manager.CallerAuthOccupancySnapshot(scopes)
	out := make([]apiKeyAuthOccupancyEntry, 0, len(items))
	for _, entry := range items {
		entry.item.Credentials = occupancy[entry.scope]
		if entry.item.Credentials == nil {
			entry.item.Credentials = []coreauth.CallerAuthOccupancy{}
		}
		out = append(out, entry.item)
	}

	c.JSON(http.StatusOK, gin.H{"items": out})
}
