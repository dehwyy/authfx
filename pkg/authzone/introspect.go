package authzone

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dehwyy/tracerfx/pkg/tracer/log"
)

const maxIntrospectBody = 1 << 20

func (v *Verifier) introspect(
	ctx context.Context,
	instance Instance,
	token string,
) (*claims, error) {
	base := instance.URL
	if base == "" {
		base = instance.Issuer
	}

	form := url.Values{}
	form.Set(
		"token",
		token,
	)

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		normalizeIssuer(base)+introspectSuffix,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: build request: %w",
			ErrProvider,
			err,
		)
	}

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.SetBasicAuth(
		instance.ClientID,
		instance.ClientSecret,
	)

	if instance.URL != "" {
		if err := setIssuerHost(
			request,
			instance,
		); err != nil {
			return nil, err
		}
	}

	response, err := v.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: introspect request: %w",
			ErrProvider,
			err,
		)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			log.FromContext(ctx).Warn(
				"authzone: close introspect body",
				"error",
				closeErr,
			)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(
		response.Body,
		maxIntrospectBody,
	))
	if err != nil {
		return nil, fmt.Errorf(
			"%w: read introspect body: %w",
			ErrProvider,
			err,
		)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"%w: introspect status %d",
			ErrProvider,
			response.StatusCode,
		)
	}

	return parseClaims(
		body,
		instance.ProjectID,
	)
}

func setIssuerHost(
	request *http.Request,
	instance Instance,
) error {
	issuer, err := url.Parse(instance.Issuer)
	if err != nil {
		return fmt.Errorf(
			"%w: parse issuer: %w",
			ErrProvider,
			err,
		)
	}

	if instance.HostHeader == "" || strings.EqualFold(
		instance.HostHeader,
		"Host",
	) {
		request.Host = issuer.Host

		return nil
	}

	request.Header.Set(
		instance.HostHeader,
		issuer.Host,
	)

	return nil
}
