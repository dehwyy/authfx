package authzone

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func SetNow(
	v *Verifier,
	now func() time.Time,
) {
	v.now = now
}

func LegacyStaffAccepted() prometheus.Counter {
	return legacyStaffAccepted
}
