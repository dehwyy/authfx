package authzone

import (
	"context"
	"time"

	"github.com/dehwyy/tracerfx/pkg/tracer/dspan"
)

func (v *Verifier) Verify(
	ctx context.Context,
	token string,
) (*Principal, error) {
	ctx, span := dspan.Start(
		ctx,
		"authzone.Verifier.Verify",
	)
	defer span.End()

	if token == "" {
		return nil, ErrUnauthenticated
	}

	key := cacheKey(token)
	if entry, ok := v.cacheGet(key); ok {
		if entry.principal == nil {
			return nil, ErrUnauthenticated
		}

		countLegacy(entry.principal)

		return entry.principal.clone(), nil
	}

	resolved, err := v.resolve(
		ctx,
		token,
	)
	if err != nil {
		if resolved.negative {
			v.cachePut(
				key,
				nil,
				v.negTTL,
			)
		}

		if isProviderError(err) {
			return nil, span.Err(err)
		}

		return nil, err
	}

	span.WithAttribute(
		"zone",
		resolved.principal.home.String(),
	)
	span.WithAttribute(
		"legacy",
		resolved.principal.legacy,
	)

	v.cachePut(
		key,
		resolved.principal,
		v.positiveTTL(resolved.exp),
	)

	countLegacy(resolved.principal)

	return resolved.principal.clone(), nil
}

func (v *Verifier) positiveTTL(exp time.Time) time.Duration {
	ttl := v.cacheTTL
	if exp.IsZero() {
		return ttl
	}

	return min(
		ttl,
		exp.Sub(v.now()),
	)
}
