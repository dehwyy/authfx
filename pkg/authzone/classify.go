package authzone

import "sort"

func (v *Verifier) classify(
	instance Instance,
	parsed *claims,
) *Principal {
	roles := map[Zone][]string{}
	legacy := false

	for _, role := range parsed.roles {
		roleZone := v.staffRoles.Zone(role)

		switch {
		case instance.Zone == ZoneStaff && roleZone == ZoneStaff:
			roles[ZoneStaff] = append(roles[ZoneStaff], role)
		case instance.Zone == ZoneClient && roleZone == ZoneClient:
			roles[ZoneClient] = append(roles[ZoneClient], role)
		case instance.Zone == ZoneClient && roleZone == ZoneStaff && v.legacy:
			roles[ZoneStaff] = append(roles[ZoneStaff], role)
			legacy = true
		}
	}

	for _, list := range roles {
		sort.Strings(list)
	}

	return &Principal{
		Issuer:   instance.Issuer,
		Subject:  parsed.subject,
		Email:    parsed.email,
		Picture:  parsed.picture,
		Metadata: parsed.metadata,
		home:     instance.Zone,
		roles:    roles,
		legacy:   legacy,
	}
}
