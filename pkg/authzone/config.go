package authzone

import "time"

const (
	defaultNegativeCacheTTL = 5 * time.Second
	defaultCacheSize        = 4096
	defaultHTTPTimeout      = 10 * time.Second
	defaultBreakerThreshold = 5
	defaultBreakerOpenFor   = 30 * time.Second
)

type Instance struct {
	Zone         Zone
	Issuer       string
	URL          string
	HostHeader   string
	ClientID     string
	ClientSecret string
	ProjectID    string
}

type RoleSet struct {
	Names    []string
	Prefixes []string
}

type Config struct {
	Instances           []Instance
	StaffRoles          RoleSet
	LegacyStaffInClient bool
	CacheTTL            time.Duration
	NegativeCacheTTL    time.Duration
	CacheSize           int
	HTTPTimeout         time.Duration
	BreakerThreshold    int
	BreakerOpenFor      time.Duration
}
