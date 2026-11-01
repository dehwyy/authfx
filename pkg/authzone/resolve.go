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
		guard := v.breakers[normalizeIssuer(instance.Issuer)]
		if !guard.allow() {
			providerErr = fmt.Errorf(
				"%w: %s circuit open",
				ErrProvider,
				instance.Zone,
			)

			continue
		}

		parsed, err := v.introspect(
			ctx,
			instance,
			token,
		)
		if err != nil {
			guard.fail()

			providerErr = err

			continue
		}

		guard.succeed()

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
