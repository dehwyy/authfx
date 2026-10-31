package authzone

import (
	"slices"
	"strings"
)

func (s RoleSet) Zone(role string) Zone {
	if slices.Contains(
		s.Names,
		role,
	) {
		return ZoneStaff
	}

	for _, prefix := range s.Prefixes {
		if prefix != "" && strings.HasPrefix(
			role,
			prefix,
		) {
			return ZoneStaff
		}
	}

	return ZoneClient
}
