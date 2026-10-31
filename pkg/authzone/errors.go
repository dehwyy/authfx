package authzone

import "errors"

var (
	ErrUnauthenticated = errors.New("authzone: unauthenticated")
	ErrProvider        = errors.New("authzone: identity provider failure")
	ErrInvalidConfig   = errors.New("authzone: invalid config")
)
