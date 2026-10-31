package authzone_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dehwyy/authfx/pkg/authzone"
)

func TestRoleSet_Zone(t *testing.T) {
	set := authzone.RoleSet{
		Names:    []string{"DEV"},
		Prefixes: []string{"STAFF_"},
	}

	require.Equal(t, authzone.ZoneStaff, set.Zone("DEV"))
	require.Equal(t, authzone.ZoneStaff, set.Zone("STAFF_X"))
	require.Equal(t, authzone.ZoneClient, set.Zone("MERCHANT"))
	require.Equal(t, authzone.ZoneClient, set.Zone("DEVX"))
	require.Equal(t, authzone.ZoneClient, set.Zone(""))
}

func validInstance(
	zone authzone.Zone,
	issuer string,
) authzone.Instance {
	return authzone.Instance{
		Zone:      zone,
		Issuer:    issuer,
		ClientID:  "cid",
		ProjectID: "pid",
	}
}

func TestNew_RejectsInvalidConfig(t *testing.T) {
	staff := validInstance(authzone.ZoneStaff, "https://staff.example.test")
	client := validInstance(authzone.ZoneClient, "https://client.example.test")

	with := func(mutate func(*authzone.Instance)) authzone.Config {
		instance := client
		mutate(&instance)

		return authzone.Config{
			Instances: []authzone.Instance{instance},
		}
	}

	tests := map[string]authzone.Config{
		"no instances": {},
		"unknown zone": with(func(i *authzone.Instance) {
			i.Zone = authzone.Zone("admin")
		}),
		"empty issuer": with(func(i *authzone.Instance) {
			i.Issuer = ""
		}),
		"issuer without scheme": with(func(i *authzone.Instance) {
			i.Issuer = "client.example.test"
		}),
		"duplicate issuer": {
			Instances: []authzone.Instance{
				client,
				validInstance(authzone.ZoneStaff, "https://client.example.test/"),
			},
		},
		"empty project": with(func(i *authzone.Instance) {
			i.ProjectID = ""
		}),
		"empty client id": with(func(i *authzone.Instance) {
			i.ClientID = ""
		}),
		"bad url": with(func(i *authzone.Instance) {
			i.URL = "nope"
		}),
		"negative ttl": {
			Instances: []authzone.Instance{client},
			CacheTTL:  -1,
		},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			verifier, err := authzone.New(cfg)

			require.ErrorIs(t, err, authzone.ErrInvalidConfig)
			require.Nil(t, verifier)
		})
	}

	verifier, err := authzone.New(authzone.Config{
		Instances: []authzone.Instance{
			client,
			staff,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, verifier)
}
