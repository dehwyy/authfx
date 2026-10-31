package authzone

import "slices"

func (p *Principal) HasRole(
	zone Zone,
	role string,
) bool {
	if p == nil {
		return false
	}

	return slices.Contains(
		p.roles[zone],
		role,
	)
}
