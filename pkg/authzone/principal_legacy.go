package authzone

func (p *Principal) Legacy() bool {
	return p != nil && p.legacy
}
