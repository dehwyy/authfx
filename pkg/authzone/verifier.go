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
	breakers   map[string]*breaker

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

	if cfg.BreakerThreshold == 0 {
		cfg.BreakerThreshold = defaultBreakerThreshold
	}

	if cfg.BreakerOpenFor == 0 {
		cfg.BreakerOpenFor = defaultBreakerOpenFor
	}

	instances := make(
		[]Instance,
		len(cfg.Instances),
	)
	copy(
		instances,
		cfg.Instances,
	)

	verifier := &Verifier{
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
		breakers:  make(map[string]*breaker, len(instances)),
	}

	for _, instance := range instances {
		verifier.breakers[normalizeIssuer(instance.Issuer)] = &breaker{
			threshold: cfg.BreakerThreshold,
			openFor:   cfg.BreakerOpenFor,
			now: func() time.Time {
				return verifier.now()
			},
		}
	}

	return verifier, nil
}
