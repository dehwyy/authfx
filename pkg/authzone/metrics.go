package authzone

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var legacyStaffAccepted = promauto.NewCounter(prometheus.CounterOpts{
	Name: "authfx_legacy_staff_accepted_total",
	Help: "Verified tokens of the client instance that carry staff roles accepted through the legacy path.",
})
