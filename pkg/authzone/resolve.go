package authzone

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type resolution struct {
	principal *Principal
	exp       time.Time
	negative  bool
}

func (v *Verifier) resolve(
	ctx context.Context,
	token string,
) (resolution, error) {
	var providerErr error

	for _, instance := range v.route(token) {
		parsed, err := v.introspect(
			ctx,
			instance,
			token,
		)
		if err != nil {
			providerErr = err

			continue
		}

		if !parsed.active {
			continue
		}

		if normalizeIssuer(parsed.issuer) != normalizeIssuer(instance.Issuer) {
			return resolution{}, fmt.Errorf(
				"%w: issuer mismatch",
				ErrUnauthenticated,
			)
		}

		return resolution{
			principal: v.classify(
				instance,
				parsed,
			),
			exp: parsed.exp,
		}, nil
	}

	if providerErr != nil {
		return resolution{}, providerErr
	}

	return resolution{negative: true}, ErrUnauthenticated
}

func isProviderError(err error) bool {
	return errors.Is(
		err,
		ErrProvider,
	)
}
