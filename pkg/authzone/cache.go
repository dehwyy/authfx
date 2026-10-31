package authzone

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type cacheEntry struct {
	principal *Principal
	expires   time.Time
}

func cacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}

func (v *Verifier) cacheGet(key string) (cacheEntry, bool) {
	if v.cacheTTL <= 0 {
		return cacheEntry{}, false
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	entry, ok := v.cache[key]
	if !ok {
		return cacheEntry{}, false
	}

	if !v.now().Before(entry.expires) {
		delete(
			v.cache,
			key,
		)

		return cacheEntry{}, false
	}

	return entry, true
}

func (v *Verifier) cachePut(
	key string,
	principal *Principal,
	ttl time.Duration,
) {
	if v.cacheTTL <= 0 || ttl <= 0 {
		return
	}

	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.cache) >= v.cacheSize {
		for existing, entry := range v.cache {
			if !now.Before(entry.expires) {
				delete(
					v.cache,
					existing,
				)
			}
		}
	}

	if len(v.cache) >= v.cacheSize {
		clear(v.cache)
	}

	v.cache[key] = cacheEntry{
		principal: principal,
		expires:   now.Add(ttl),
	}
}
