package authzone

import (
	"maps"
	"slices"
)

func (p *Principal) clone() *Principal {
	cloned := *p
	cloned.Metadata = maps.Clone(p.Metadata)
	cloned.roles = make(
		map[Zone][]string,
		len(p.roles),
	)

	for zone, roles := range p.roles {
		cloned.roles[zone] = slices.Clone(roles)
	}

	return &cloned
}
