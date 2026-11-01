package authzone

import (
	"fmt"
	"net/url"
	"strings"
)

func validateConfig(cfg Config) error {
	if len(cfg.Instances) == 0 {
		return fmt.Errorf(
			"%w: no instances",
			ErrInvalidConfig,
		)
	}

	if cfg.CacheTTL < 0 || cfg.NegativeCacheTTL < 0 || cfg.CacheSize < 0 || cfg.HTTPTimeout < 0 || cfg.BreakerThreshold < 0 || cfg.BreakerOpenFor < 0 {
		return fmt.Errorf(
			"%w: negative cache or timeout setting",
			ErrInvalidConfig,
		)
	}

	seen := make(
		map[string]struct{},
		len(cfg.Instances),
	)
	for index, instance := range cfg.Instances {
		if err := validateInstance(
			index,
			instance,
		); err != nil {
			return err
		}

		issuer := normalizeIssuer(instance.Issuer)
		if _, dup := seen[issuer]; dup {
			return fmt.Errorf(
				"%w: instance %d: duplicate issuer",
				ErrInvalidConfig,
				index,
			)
		}

		seen[issuer] = struct{}{}
	}

	return nil
}

func validateInstance(
	index int,
	instance Instance,
) error {
	if instance.Zone != ZoneStaff && instance.Zone != ZoneClient {
		return fmt.Errorf(
			"%w: instance %d: unknown zone %q",
			ErrInvalidConfig,
			index,
			instance.Zone,
		)
	}

	if !hasScheme(instance.Issuer) {
		return fmt.Errorf(
			"%w: instance %d: issuer must be an absolute http(s) url",
			ErrInvalidConfig,
			index,
		)
	}

	if instance.URL != "" && !hasScheme(instance.URL) {
		return fmt.Errorf(
			"%w: instance %d: url must be an absolute http(s) url",
			ErrInvalidConfig,
			index,
		)
	}

	if instance.ProjectID == "" {
		return fmt.Errorf(
			"%w: instance %d: empty project id",
			ErrInvalidConfig,
			index,
		)
	}

	if instance.ClientID == "" {
		return fmt.Errorf(
			"%w: instance %d: empty client id",
			ErrInvalidConfig,
			index,
		)
	}

	return nil
}

func hasScheme(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	return parsed.Host != ""
}

func normalizeIssuer(issuer string) string {
	return strings.TrimRight(
		issuer,
		"/",
	)
}
