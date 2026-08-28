package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type callerExclusiveOwnerStore interface {
	Claim(ctx context.Context, resourceKey, owner string, record callerExclusiveOwnerRecord, ttl time.Duration) (bool, error)
	Get(ctx context.Context, resourceKey string) (callerExclusiveOwnerRecord, bool, error)
	Delete(ctx context.Context, resourceKey string) error
	Snapshot(ctx context.Context, allowedOwners map[string]struct{}) (map[string]callerExclusiveOwnerRecord, error)
	Prune(ctx context.Context, ttl time.Duration) error
	Close() error
}

type redisCallerExclusiveOwnerStore struct {
	client    *redis.Client
	keyPrefix string
}

const redisCallerExclusiveOwnerOwnerField = "owner"
const redisCallerExclusiveOwnerSequenceField = "sequence"
const redisCallerExclusiveOwnerClaimedAtField = "claimed_at"

func newRedisCallerExclusiveOwnerStore(cfg internalconfig.CallerExclusiveAuthRedisConfig) (*redisCallerExclusiveOwnerStore, error) {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	keyPrefix := strings.TrimSpace(cfg.KeyPrefix)
	if keyPrefix == "" {
		keyPrefix = "cliproxy:caller-exclusive-auth"
	}
	if strings.TrimSpace(keyPrefix) == "" {
		return nil, fmt.Errorf("redis key prefix is required")
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: strings.TrimSpace(cfg.Username),
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return &redisCallerExclusiveOwnerStore{client: client, keyPrefix: keyPrefix}, nil
}

func (s *redisCallerExclusiveOwnerStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *redisCallerExclusiveOwnerStore) redisKey(resourceKey string) string {
	resourceKey = strings.TrimSpace(resourceKey)
	if resourceKey == "" {
		return ""
	}
	return s.keyPrefix + ":" + base64.RawURLEncoding.EncodeToString([]byte(resourceKey))
}

func (s *redisCallerExclusiveOwnerStore) Claim(ctx context.Context, resourceKey, owner string, record callerExclusiveOwnerRecord, ttl time.Duration) (bool, error) {
	if s == nil || s.client == nil {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resourceKey = s.redisKey(resourceKey)
	owner = strings.TrimSpace(owner)
	if resourceKey == "" || owner == "" || ttl <= 0 {
		return false, nil
	}
	if record.ClaimedAt.IsZero() {
		record.ClaimedAt = time.Now()
	}
	script := redis.NewScript(`
local currentOwner = redis.call("HGET", KEYS[1], "` + redisCallerExclusiveOwnerOwnerField + `")
if (not currentOwner) or currentOwner == "" or currentOwner == ARGV[1] then
  redis.call("HSET", KEYS[1], "` + redisCallerExclusiveOwnerOwnerField + `", ARGV[1], "` + redisCallerExclusiveOwnerSequenceField + `", ARGV[2], "` + redisCallerExclusiveOwnerClaimedAtField + `", ARGV[3])
  redis.call("PEXPIRE", KEYS[1], ARGV[4])
  return 1
end
return 0
`)
	result, errRun := script.Run(ctx, s.client, []string{resourceKey}, owner, fmt.Sprintf("%d", record.Sequence), fmt.Sprintf("%d", record.ClaimedAt.UnixNano()), fmt.Sprintf("%d", ttl.Milliseconds())).Int64()
	if errRun != nil {
		return false, errRun
	}
	return result == 1, nil
}

func (s *redisCallerExclusiveOwnerStore) Get(ctx context.Context, resourceKey string) (callerExclusiveOwnerRecord, bool, error) {
	if s == nil || s.client == nil {
		return callerExclusiveOwnerRecord{}, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resourceKey = s.redisKey(resourceKey)
	if resourceKey == "" {
		return callerExclusiveOwnerRecord{}, false, nil
	}
	values, err := s.client.HGetAll(ctx, resourceKey).Result()
	if err != nil {
		return callerExclusiveOwnerRecord{}, false, err
	}
	owner := strings.TrimSpace(values[redisCallerExclusiveOwnerOwnerField])
	if owner == "" {
		return callerExclusiveOwnerRecord{}, false, nil
	}
	record := callerExclusiveOwnerRecord{Owner: owner}
	if rawSequence := strings.TrimSpace(values[redisCallerExclusiveOwnerSequenceField]); rawSequence != "" {
		if parsed, errParse := parseUint64(rawSequence); errParse == nil {
			record.Sequence = parsed
		}
	}
	if rawClaimedAt := strings.TrimSpace(values[redisCallerExclusiveOwnerClaimedAtField]); rawClaimedAt != "" {
		if parsed, errParse := parseInt64(rawClaimedAt); errParse == nil && parsed > 0 {
			record.ClaimedAt = time.Unix(0, parsed)
		}
	}
	return record, true, nil
}

func (s *redisCallerExclusiveOwnerStore) Delete(ctx context.Context, resourceKey string) error {
	if s == nil || s.client == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resourceKey = s.redisKey(resourceKey)
	if resourceKey == "" {
		return nil
	}
	return s.client.Del(ctx, resourceKey).Err()
}

func (s *redisCallerExclusiveOwnerStore) Snapshot(ctx context.Context, allowedOwners map[string]struct{}) (map[string]callerExclusiveOwnerRecord, error) {
	result := make(map[string]callerExclusiveOwnerRecord)
	if s == nil || s.client == nil {
		return result, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cursor := uint64(0)
	pattern := s.keyPrefix + ":*"
	for {
		keys, nextCursor, errScan := s.client.Scan(ctx, cursor, pattern, 256).Result()
		if errScan != nil {
			return nil, errScan
		}
		for _, key := range keys {
			record, ok, errGet := s.getByRedisKey(ctx, key)
			if errGet != nil {
				return nil, errGet
			}
			if !ok {
				continue
			}
			if len(allowedOwners) > 0 {
				if _, okOwner := allowedOwners[strings.TrimSpace(record.Owner)]; !okOwner {
					continue
				}
			}
			resourceKey, okResource := s.resourceKeyFromRedisKey(key)
			if !okResource {
				continue
			}
			result[resourceKey] = record
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result, nil
}

func (s *redisCallerExclusiveOwnerStore) Prune(ctx context.Context, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = 72 * time.Hour
	}
	cursor := uint64(0)
	pattern := s.keyPrefix + ":*"
	now := time.Now()
	for {
		keys, nextCursor, errScan := s.client.Scan(ctx, cursor, pattern, 256).Result()
		if errScan != nil {
			return errScan
		}
		for _, key := range keys {
			record, ok, errGet := s.getByRedisKey(ctx, key)
			if errGet != nil {
				return errGet
			}
			if !ok || record.ClaimedAt.IsZero() || now.Sub(record.ClaimedAt) <= ttl {
				continue
			}
			if errDel := s.client.Del(ctx, key).Err(); errDel != nil {
				return errDel
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (s *redisCallerExclusiveOwnerStore) getByRedisKey(ctx context.Context, key string) (callerExclusiveOwnerRecord, bool, error) {
	values, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return callerExclusiveOwnerRecord{}, false, err
	}
	owner := strings.TrimSpace(values[redisCallerExclusiveOwnerOwnerField])
	if owner == "" {
		return callerExclusiveOwnerRecord{}, false, nil
	}
	record := callerExclusiveOwnerRecord{Owner: owner}
	if rawSequence := strings.TrimSpace(values[redisCallerExclusiveOwnerSequenceField]); rawSequence != "" {
		if parsed, errParse := parseUint64(rawSequence); errParse == nil {
			record.Sequence = parsed
		}
	}
	if rawClaimedAt := strings.TrimSpace(values[redisCallerExclusiveOwnerClaimedAtField]); rawClaimedAt != "" {
		if parsed, errParse := parseInt64(rawClaimedAt); errParse == nil && parsed > 0 {
			record.ClaimedAt = time.Unix(0, parsed)
		}
	}
	return record, true, nil
}

func (s *redisCallerExclusiveOwnerStore) resourceKeyFromRedisKey(redisKey string) (string, bool) {
	prefix := s.keyPrefix + ":"
	if !strings.HasPrefix(redisKey, prefix) {
		return "", false
	}
	encoded := strings.TrimPrefix(redisKey, prefix)
	if encoded == "" {
		return "", false
	}
	raw, errDecode := base64.RawURLEncoding.DecodeString(encoded)
	if errDecode != nil {
		return "", false
	}
	return string(raw), true
}

func parseUint64(value string) (uint64, error) {
	var parsed uint64
	_, err := fmt.Sscanf(value, "%d", &parsed)
	return parsed, err
}

func parseInt64(value string) (int64, error) {
	var parsed int64
	_, err := fmt.Sscanf(value, "%d", &parsed)
	return parsed, err
}
