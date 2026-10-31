package authzone

func (p *Principal) HasAnyRole(
	zone Zone,
	roles []string,
) bool {
	for _, role := range roles {
		if p.HasRole(
			zone,
			role,
		) {
			return true
		}
	}

	return false
}
