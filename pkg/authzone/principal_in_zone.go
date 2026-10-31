package authzone

func (p *Principal) InZone(zone Zone) bool {
	if p == nil {
		return false
	}

	return p.home == zone || len(p.roles[zone]) > 0
}
