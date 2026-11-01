package authzone

func (p *Principal) Legacy() bool {
	return p != nil && p.legacy
}

func countLegacy(principal *Principal) {
	if principal.Legacy() {
		legacyStaffAccepted.Inc()
	}
}
