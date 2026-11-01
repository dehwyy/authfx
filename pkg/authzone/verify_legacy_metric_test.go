package authzone_test

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/dehwyy/authfx/pkg/authzone"
)

func TestVerify_LegacyStaffAcceptanceCounted(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("p-client", []string{"DEV", "MERCHANT"}, nil)
	cfg := s.config(true)
	cfg.CacheTTL = time.Minute
	verifier, err := authzone.New(cfg)
	require.NoError(t, err)
	token := jwtFor(s.client.server.URL)
	before := testutil.ToFloat64(authzone.LegacyStaffAccepted())

	for range 3 {
		principal, verifyErr := verifier.Verify(context.Background(), token)
		require.NoError(t, verifyErr)
		require.True(t, principal.Legacy())
	}

	require.Equal(t, int32(1), s.client.calls.Load())
	require.InDelta(t, before+3, testutil.ToFloat64(authzone.LegacyStaffAccepted()), 0)
}

func TestVerify_NonLegacyAcceptanceNotCounted(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("p-client", []string{"MERCHANT"}, nil)
	s.staff.activate("p-staff", []string{"DEV"}, nil)
	verifier := s.verifier(t, true)
	before := testutil.ToFloat64(authzone.LegacyStaffAccepted())

	_, err := verifier.Verify(context.Background(), jwtFor(s.client.server.URL))
	require.NoError(t, err)
	_, err = verifier.Verify(context.Background(), jwtFor(s.staff.server.URL))
	require.NoError(t, err)

	require.InDelta(t, before, testutil.ToFloat64(authzone.LegacyStaffAccepted()), 0)
}
