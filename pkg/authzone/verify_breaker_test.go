package authzone_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dehwyy/authfx/pkg/authzone"
)

func TestVerify_StaffFailuresDoNotRejectClientTokens(t *testing.T) {
	s := newStand(t, nil)
	s.staff.respond(http.StatusServiceUnavailable, map[string]any{})
	s.client.activate("p-client", []string{"MERCHANT"}, nil)
	verifier := s.verifier(t, false)

	staffToken := jwtFor(s.staff.server.URL)
	for range 10 {
		_, err := verifier.Verify(context.Background(), staffToken)
		require.ErrorIs(t, err, authzone.ErrProvider)
	}

	require.Equal(t, int32(5), s.staff.calls.Load())

	principal, err := verifier.Verify(context.Background(), jwtFor(s.client.server.URL))
	require.NoError(t, err)
	require.True(t, principal.InZone(authzone.ZoneClient))
}

func TestVerify_ClientFailuresDoNotOpenStaffBreaker(t *testing.T) {
	s := newStand(t, nil)
	s.client.respond(http.StatusServiceUnavailable, map[string]any{})
	s.staff.activate("p-staff", []string{"DEV"}, nil)
	verifier := s.verifier(t, false)

	for range 10 {
		_, err := verifier.Verify(context.Background(), jwtFor(s.client.server.URL))
		require.ErrorIs(t, err, authzone.ErrProvider)
	}

	require.Equal(t, int32(5), s.client.calls.Load())

	principal, err := verifier.Verify(context.Background(), jwtFor(s.staff.server.URL))
	require.NoError(t, err)
	require.True(t, principal.InZone(authzone.ZoneStaff))
}

func TestVerify_OpaqueStaffTokenPassesWhileClientBreakerOpen(t *testing.T) {
	s := newStand(t, nil)
	s.client.respond(http.StatusServiceUnavailable, map[string]any{})
	s.staff.activate("p-staff", []string{"DEV"}, nil)
	verifier := s.verifier(t, false)

	for range 10 {
		principal, err := verifier.Verify(context.Background(), "opaque-token")
		require.NoError(t, err)
		require.True(t, principal.InZone(authzone.ZoneStaff))
	}

	require.Equal(t, int32(5), s.client.calls.Load())
}

func TestVerify_BreakerHalfOpenRecovers(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	offset := time.Duration(0)
	s := newStand(t, nil)
	s.staff.respond(http.StatusServiceUnavailable, map[string]any{})
	verifier := s.verifier(t, false)
	authzone.SetNow(verifier, func() time.Time { return now.Add(offset) })
	token := jwtFor(s.staff.server.URL)

	for range 6 {
		_, err := verifier.Verify(context.Background(), token)
		require.ErrorIs(t, err, authzone.ErrProvider)
	}

	require.Equal(t, int32(5), s.staff.calls.Load())

	offset = 31 * time.Second
	_, err := verifier.Verify(context.Background(), token)
	require.ErrorIs(t, err, authzone.ErrProvider)
	require.Equal(t, int32(6), s.staff.calls.Load())

	_, err = verifier.Verify(context.Background(), token)
	require.ErrorIs(t, err, authzone.ErrProvider)
	require.Equal(t, int32(6), s.staff.calls.Load())

	offset = 62 * time.Second
	s.staff.activate("p-staff", []string{"DEV"}, nil)
	principal, err := verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	require.True(t, principal.InZone(authzone.ZoneStaff))

	s.staff.respond(http.StatusServiceUnavailable, map[string]any{})
	_, err = verifier.Verify(context.Background(), token)
	require.ErrorIs(t, err, authzone.ErrProvider)
	require.Equal(t, int32(8), s.staff.calls.Load())
}

func TestVerify_SuccessResetsFailureStreak(t *testing.T) {
	s := newStand(t, nil)
	verifier := s.verifier(t, false)
	token := jwtFor(s.staff.server.URL)

	for range 4 {
		s.staff.respond(http.StatusServiceUnavailable, map[string]any{})
		_, err := verifier.Verify(context.Background(), token)
		require.ErrorIs(t, err, authzone.ErrProvider)
	}

	s.staff.activate("p-staff", []string{"DEV"}, nil)
	_, err := verifier.Verify(context.Background(), token)
	require.NoError(t, err)

	s.staff.respond(http.StatusServiceUnavailable, map[string]any{})
	for range 4 {
		_, err = verifier.Verify(context.Background(), token)
		require.ErrorIs(t, err, authzone.ErrProvider)
	}

	require.Equal(t, int32(9), s.staff.calls.Load())
}

func TestVerify_BreakerSettingsFromConfig(t *testing.T) {
	s := newStand(t, nil)
	s.staff.respond(http.StatusServiceUnavailable, map[string]any{})
	cfg := s.config(false)
	cfg.BreakerThreshold = 2
	verifier, err := authzone.New(cfg)
	require.NoError(t, err)
	token := jwtFor(s.staff.server.URL)

	for range 5 {
		_, err = verifier.Verify(context.Background(), token)
		require.ErrorIs(t, err, authzone.ErrProvider)
	}

	require.Equal(t, int32(2), s.staff.calls.Load())
}

func TestNew_RejectsNegativeBreakerSettings(t *testing.T) {
	s := newStand(t, nil)
	cfg := s.config(false)
	cfg.BreakerOpenFor = -time.Second

	_, err := authzone.New(cfg)
	require.ErrorIs(t, err, authzone.ErrInvalidConfig)
}
