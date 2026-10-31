package authzone

import (
	"net/http"
	"sync"
	"time"
)

type Verifier struct {
	instances  []Instance
	staffRoles RoleSet
	legacy     bool
	client     *http.Client
	cacheTTL   time.Duration
	negTTL     time.Duration
	cacheSize  int
	now        func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

func New(cfg Config) (*Verifier, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	if cfg.NegativeCacheTTL == 0 {
		cfg.NegativeCacheTTL = defaultNegativeCacheTTL
	}

	if cfg.CacheSize == 0 {
		cfg.CacheSize = defaultCacheSize
	}

	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}

	instances := make(
		[]Instance,
		len(cfg.Instances),
	)
	copy(
		instances,
		cfg.Instances,
	)

	return &Verifier{
		instances:  instances,
		staffRoles: cfg.StaffRoles,
		legacy:     cfg.LegacyStaffInClient,
		client: &http.Client{
			Timeout: cfg.HTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cacheTTL:  cfg.CacheTTL,
		negTTL:    cfg.NegativeCacheTTL,
		cacheSize: cfg.CacheSize,
		now:       time.Now,
		cache:     make(map[string]cacheEntry),
	}, nil
}
