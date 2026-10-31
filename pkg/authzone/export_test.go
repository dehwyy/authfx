package authzone

import "time"

func SetNow(
	v *Verifier,
	now func() time.Time,
) {
	v.now = now
}
