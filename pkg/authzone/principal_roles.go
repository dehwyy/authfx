package authzone

import "slices"

func (p *Principal) Roles(zone Zone) []string {
	if p == nil {
		return nil
	}

	return slices.Clone(p.roles[zone])
}
