package authzone_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dehwyy/authfx/pkg/authzone"
)

type provider struct {
	server *httptest.Server
	calls  atomic.Int32

	mu       sync.Mutex
	status   int
	body     map[string]any
	lastUser string
	lastPass string
	lastPath string
	lastVerb string
	lastTok  string
	lastHost string
	lastHdrs http.Header
	order    *[]string
	name     string
}

func newProvider(
	t *testing.T,
	name string,
	order *[]string,
) *provider {
	p := &provider{
		status: http.StatusOK,
		order:  order,
		name:   name,
		body: map[string]any{
			"active": false,
		},
	}

	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)

		p.mu.Lock()
		defer p.mu.Unlock()

		p.lastUser, p.lastPass, _ = r.BasicAuth()
		p.lastPath = r.URL.Path
		p.lastVerb = r.Method
		p.lastHost = r.Host
		p.lastHdrs = r.Header.Clone()
		require.NoError(t, r.ParseForm())
		p.lastTok = r.PostForm.Get("token")

		if p.order != nil {
			*p.order = append(*p.order, p.name)
		}

		w.WriteHeader(p.status)
		require.NoError(t, json.NewEncoder(w).Encode(p.body))
	}))
	t.Cleanup(p.server.Close)

	return p
}

func (p *provider) respond(
	status int,
	body map[string]any,
) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.status = status
	p.body = body
}

func (p *provider) activate(
	project string,
	roles []string,
	extra map[string]any,
) {
	roleClaim := map[string]any{}
	for _, role := range roles {
		roleClaim[role] = map[string]string{"1": "org"}
	}

	body := map[string]any{
		"active": true,
		"iss":    p.server.URL,
		"sub":    "user-1",
		"urn:zitadel:iam:org:project:" + project + ":roles": roleClaim,
	}
	for key, value := range extra {
		body[key] = value
	}

	p.respond(http.StatusOK, body)
}

type stand struct {
	client *provider
	staff  *provider
}

func newStand(
	t *testing.T,
	order *[]string,
) *stand {
	return &stand{
		client: newProvider(t, "client", order),
		staff:  newProvider(t, "staff", order),
	}
}

func (s *stand) config(legacy bool) authzone.Config {
	return authzone.Config{
		Instances: []authzone.Instance{
			{
				Zone:         authzone.ZoneClient,
				Issuer:       s.client.server.URL,
				ClientID:     "cid-client",
				ClientSecret: "sec-client",
				ProjectID:    "p-client",
			},
			{
				Zone:         authzone.ZoneStaff,
				Issuer:       s.staff.server.URL,
				ClientID:     "cid-staff",
				ClientSecret: "sec-staff",
				ProjectID:    "p-staff",
			},
		},
		StaffRoles: authzone.RoleSet{
			Names:    []string{"DEV", "ADMIN_READ"},
			Prefixes: []string{"STAFF_"},
		},
		LegacyStaffInClient: legacy,
	}
}

func (s *stand) verifier(
	t *testing.T,
	legacy bool,
) *authzone.Verifier {
	verifier, err := authzone.New(s.config(legacy))
	require.NoError(t, err)

	return verifier
}

func jwtFor(iss string) string {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "RS256"})
	payload, _ := json.Marshal(map[string]string{"iss": iss})

	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + ".sig"
}

func TestVerify_StaffInstanceDropsClientRoles(t *testing.T) {
	s := newStand(t, nil)
	s.staff.activate("p-staff", []string{"STAFF_SUPPORT_VIEW", "MERCHANT", "CLIENT_TX_VIEW"}, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.staff.server.URL))

	require.NoError(t, err)
	require.Equal(t, []string{"STAFF_SUPPORT_VIEW"}, principal.Roles(authzone.ZoneStaff))
	require.Empty(t, principal.Roles(authzone.ZoneClient))
	require.False(t, principal.InZone(authzone.ZoneClient))
	require.True(t, principal.InZone(authzone.ZoneStaff))
	require.False(t, principal.HasRole(authzone.ZoneClient, "MERCHANT"))
	require.False(t, principal.HasAnyRole(authzone.ZoneClient, []string{"MERCHANT", "CLIENT_TX_VIEW"}))
	require.False(t, principal.Legacy())
}

func TestVerify_ClientInstanceDropsStaffRolesWhenLegacyOff(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("p-client", []string{"MERCHANT", "DEV", "STAFF_AUDIT_VIEW"}, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.client.server.URL))

	require.NoError(t, err)
	require.Equal(t, []string{"MERCHANT"}, principal.Roles(authzone.ZoneClient))
	require.False(t, principal.InZone(authzone.ZoneStaff))
	require.False(t, principal.HasRole(authzone.ZoneClient, "DEV"))
	require.False(t, principal.HasRole(authzone.ZoneStaff, "DEV"))
	require.False(t, principal.Legacy())
}

func TestVerify_LegacySplitsMixedRoles(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("p-client", []string{"MERCHANT", "STAFF_AUDIT_VIEW", "DEV"}, nil)

	principal, err := s.verifier(t, true).Verify(context.Background(), jwtFor(s.client.server.URL))

	require.NoError(t, err)
	require.Equal(t, []string{"DEV", "STAFF_AUDIT_VIEW"}, principal.Roles(authzone.ZoneStaff))
	require.Equal(t, []string{"MERCHANT"}, principal.Roles(authzone.ZoneClient))
	require.False(t, principal.HasRole(authzone.ZoneClient, "DEV"))
	require.False(t, principal.HasRole(authzone.ZoneStaff, "MERCHANT"))
	require.True(t, principal.HasAnyRole(authzone.ZoneStaff, []string{"X", "DEV"}))
	require.True(t, principal.Legacy())
}

func TestVerify_IgnoresRolesOfOtherProject(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("999", []string{"MERCHANT", "DEV"}, nil)

	principal, err := s.verifier(t, true).Verify(context.Background(), jwtFor(s.client.server.URL))

	require.NoError(t, err)
	require.Empty(t, principal.Roles(authzone.ZoneClient))
	require.Empty(t, principal.Roles(authzone.ZoneStaff))
	require.True(t, principal.InZone(authzone.ZoneClient))
	require.False(t, principal.InZone(authzone.ZoneStaff))
}

func TestVerify_RolesReturnedAsCopy(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("p-client", []string{"MERCHANT"}, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.client.server.URL))
	require.NoError(t, err)

	principal.Roles(authzone.ZoneClient)[0] = "DEV"

	require.Equal(t, []string{"MERCHANT"}, principal.Roles(authzone.ZoneClient))
}

func TestVerify_JWTRoutedByIssuer(t *testing.T) {
	s := newStand(t, nil)
	s.staff.activate("p-staff", []string{"DEV"}, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.staff.server.URL))

	require.NoError(t, err)
	require.True(t, principal.InZone(authzone.ZoneStaff))
	require.Equal(t, int32(0), s.client.calls.Load())
	require.Equal(t, int32(1), s.staff.calls.Load())
}

func TestVerify_UnknownJWTIssuerRejectedWithoutCalls(t *testing.T) {
	s := newStand(t, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor("https://evil.example"))

	require.ErrorIs(t, err, authzone.ErrUnauthenticated)
	require.Nil(t, principal)
	require.Equal(t, int32(0), s.client.calls.Load())
	require.Equal(t, int32(0), s.staff.calls.Load())
}

func TestVerify_IssuerMismatchRejected(t *testing.T) {
	s := newStand(t, nil)
	s.staff.activate("p-staff", []string{"DEV"}, map[string]any{"iss": s.client.server.URL})

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.staff.server.URL))

	require.ErrorIs(t, err, authzone.ErrUnauthenticated)
	require.Nil(t, principal)
}

func TestVerify_MissingIssuerInActiveResponseRejected(t *testing.T) {
	s := newStand(t, nil)
	s.client.respond(http.StatusOK, map[string]any{"active": true, "sub": "u"})

	_, err := s.verifier(t, false).Verify(context.Background(), "opaque")

	require.ErrorIs(t, err, authzone.ErrUnauthenticated)
}

func TestVerify_OpaqueTriesInstancesInOrder(t *testing.T) {
	order := []string{}
	s := newStand(t, &order)
	s.staff.activate("p-staff", []string{"DEV"}, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), "opaque-token")

	require.NoError(t, err)
	require.True(t, principal.InZone(authzone.ZoneStaff))
	require.Equal(t, []string{"client", "staff"}, order)
}

func TestVerify_OpaqueProviderErrorIsNotUnauthenticated(t *testing.T) {
	s := newStand(t, nil)
	s.client.respond(http.StatusInternalServerError, map[string]any{})

	_, err := s.verifier(t, false).Verify(context.Background(), "opaque-token")
	require.ErrorIs(t, err, authzone.ErrProvider)
	require.NotErrorIs(t, err, authzone.ErrUnauthenticated)

	s.staff.activate("p-staff", []string{"DEV"}, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), "opaque-token")
	require.NoError(t, err)
	require.True(t, principal.InZone(authzone.ZoneStaff))
	require.False(t, principal.InZone(authzone.ZoneClient))
}

func TestVerify_InvalidJSONIsProviderError(t *testing.T) {
	s := newStand(t, nil)
	s.client.respond(http.StatusOK, nil)
	s.client.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("<html>"))
		require.NoError(t, err)
	})

	_, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.client.server.URL))

	require.ErrorIs(t, err, authzone.ErrProvider)
}

func TestVerify_InactiveIsUnauthenticated(t *testing.T) {
	s := newStand(t, nil)

	principal, err := s.verifier(t, false).Verify(context.Background(), "opaque-token")

	require.ErrorIs(t, err, authzone.ErrUnauthenticated)
	require.Nil(t, principal)
	require.Equal(t, int32(1), s.client.calls.Load())
	require.Equal(t, int32(1), s.staff.calls.Load())
}

func TestVerify_EmptyTokenRejectedWithoutCalls(t *testing.T) {
	s := newStand(t, nil)

	_, err := s.verifier(t, false).Verify(context.Background(), "")

	require.ErrorIs(t, err, authzone.ErrUnauthenticated)
	require.Equal(t, int32(0), s.client.calls.Load())
	require.Equal(t, int32(0), s.staff.calls.Load())
}

func TestVerify_SendsInstanceCredentials(t *testing.T) {
	s := newStand(t, nil)
	s.staff.activate("p-staff", []string{"DEV"}, nil)

	_, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.staff.server.URL))
	require.NoError(t, err)

	s.staff.mu.Lock()
	defer s.staff.mu.Unlock()

	require.Equal(t, "cid-staff", s.staff.lastUser)
	require.Equal(t, "sec-staff", s.staff.lastPass)
	require.Equal(t, "/oauth/v2/introspect", s.staff.lastPath)
	require.Equal(t, http.MethodPost, s.staff.lastVerb)
	require.Equal(t, jwtFor(s.staff.server.URL), s.staff.lastTok)
}

func TestVerify_UsesURLWithIssuerHost(t *testing.T) {
	for name, header := range map[string]string{
		"default host": "",
		"custom":       "X-Forwarded-Host",
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t, "p", nil)
			p.respond(http.StatusOK, map[string]any{
				"active": true,
				"iss":    "https://auth.example.test",
				"sub":    "u",
			})

			verifier, err := authzone.New(authzone.Config{
				Instances: []authzone.Instance{
					{
						Zone:       authzone.ZoneStaff,
						Issuer:     "https://auth.example.test",
						URL:        p.server.URL,
						HostHeader: header,
						ClientID:   "cid",
						ProjectID:  "pid",
					},
				},
			})
			require.NoError(t, err)

			_, err = verifier.Verify(context.Background(), "opaque")
			require.NoError(t, err)

			p.mu.Lock()
			defer p.mu.Unlock()

			if header == "" {
				require.Equal(t, "auth.example.test", p.lastHost)

				return
			}

			require.Equal(t, "auth.example.test", p.lastHdrs.Get(header))
		})
	}
}

func TestVerify_MetadataDecoded(t *testing.T) {
	s := newStand(t, nil)
	s.client.activate("p-client", []string{"MERCHANT"}, map[string]any{
		"urn:zitadel:iam:user:metadata": map[string]string{
			"merchant_id": base64.StdEncoding.EncodeToString([]byte("m-1")),
		},
		"email":   "a@b.test",
		"picture": "https://img.test/a.png",
	})

	principal, err := s.verifier(t, false).Verify(context.Background(), jwtFor(s.client.server.URL))

	require.NoError(t, err)
	require.Equal(t, "m-1", principal.Metadata["merchant_id"])
	require.Equal(t, "user-1", principal.Subject)
	require.Equal(t, "a@b.test", principal.Email)
	require.Equal(t, "https://img.test/a.png", principal.Picture)
	require.Equal(t, s.client.server.URL, principal.Issuer)
}

func TestVerify_CachesPositiveAndNegative(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	t.Run("positive", func(t *testing.T) {
		s := newStand(t, nil)
		s.client.activate("p-client", []string{"MERCHANT"}, nil)
		cfg := s.config(false)
		cfg.CacheTTL = 30 * time.Second
		verifier, err := authzone.New(cfg)
		require.NoError(t, err)
		authzone.SetNow(verifier, clock)

		token := jwtFor(s.client.server.URL)
		first, err := verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		second, err := verifier.Verify(context.Background(), token)
		require.NoError(t, err)

		require.Equal(t, int32(1), s.client.calls.Load())
		require.Equal(t, first.Roles(authzone.ZoneClient), second.Roles(authzone.ZoneClient))
	})

	t.Run("negative", func(t *testing.T) {
		s := newStand(t, nil)
		cfg := s.config(false)
		cfg.CacheTTL = 30 * time.Second
		verifier, err := authzone.New(cfg)
		require.NoError(t, err)
		offset := time.Duration(0)
		authzone.SetNow(verifier, func() time.Time { return now.Add(offset) })

		_, err = verifier.Verify(context.Background(), "opaque")
		require.ErrorIs(t, err, authzone.ErrUnauthenticated)
		offset = 4 * time.Second
		_, err = verifier.Verify(context.Background(), "opaque")
		require.ErrorIs(t, err, authzone.ErrUnauthenticated)
		require.Equal(t, int32(1), s.client.calls.Load())

		offset = 6 * time.Second
		_, err = verifier.Verify(context.Background(), "opaque")
		require.ErrorIs(t, err, authzone.ErrUnauthenticated)
		require.Equal(t, int32(2), s.client.calls.Load())
	})

	t.Run("exp shortens entry", func(t *testing.T) {
		s := newStand(t, nil)
		s.client.activate("p-client", []string{"MERCHANT"}, map[string]any{
			"exp": now.Add(10 * time.Second).Unix(),
		})
		cfg := s.config(false)
		cfg.CacheTTL = 30 * time.Second
		verifier, err := authzone.New(cfg)
		require.NoError(t, err)
		offset := time.Duration(0)
		authzone.SetNow(verifier, func() time.Time { return now.Add(offset) })

		token := jwtFor(s.client.server.URL)
		_, err = verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		offset = 9 * time.Second
		_, err = verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		require.Equal(t, int32(1), s.client.calls.Load())

		offset = 11 * time.Second
		_, err = verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		require.Equal(t, int32(2), s.client.calls.Load())
	})

	t.Run("ttl zero disables", func(t *testing.T) {
		s := newStand(t, nil)
		s.client.activate("p-client", []string{"MERCHANT"}, nil)
		verifier := s.verifier(t, false)

		token := jwtFor(s.client.server.URL)
		_, err := verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		_, err = verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		_, err = verifier.Verify(context.Background(), "opaque")
		require.NoError(t, err)

		require.Equal(t, int32(3), s.client.calls.Load())
	})

	t.Run("provider errors are not cached", func(t *testing.T) {
		s := newStand(t, nil)
		s.client.respond(http.StatusInternalServerError, map[string]any{})
		s.staff.respond(http.StatusInternalServerError, map[string]any{})
		cfg := s.config(false)
		cfg.CacheTTL = 30 * time.Second
		verifier, err := authzone.New(cfg)
		require.NoError(t, err)

		_, err = verifier.Verify(context.Background(), "opaque")
		require.ErrorIs(t, err, authzone.ErrProvider)
		_, err = verifier.Verify(context.Background(), "opaque")
		require.ErrorIs(t, err, authzone.ErrProvider)

		require.Equal(t, int32(2), s.client.calls.Load())
	})

	t.Run("cache size bound", func(t *testing.T) {
		s := newStand(t, nil)
		cfg := s.config(false)
		cfg.CacheTTL = 30 * time.Second
		cfg.CacheSize = 2
		verifier, err := authzone.New(cfg)
		require.NoError(t, err)

		for _, token := range []string{"a", "b", "c", "d"} {
			_, err = verifier.Verify(context.Background(), token)
			require.ErrorIs(t, err, authzone.ErrUnauthenticated)
		}

		require.Equal(t, int32(4), s.client.calls.Load())
	})
}

func singleInstanceConfig(
	issuer string,
	baseURL string,
) authzone.Config {
	return authzone.Config{
		Instances: []authzone.Instance{
			{
				Zone:      authzone.ZoneClient,
				Issuer:    issuer,
				URL:       baseURL,
				ClientID:  "cid",
				ProjectID: "pid",
			},
		},
	}
}

func TestVerify_RedirectNotFollowed(t *testing.T) {
	target := newProvider(t, "target", nil)
	target.respond(http.StatusOK, map[string]any{
		"active": true,
		"iss":    "https://auth.example.test",
	})

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.server.URL+"/oauth/v2/introspect", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	verifier, err := authzone.New(singleInstanceConfig("https://auth.example.test", redirector.URL))
	require.NoError(t, err)

	principal, err := verifier.Verify(context.Background(), "secret-token")

	require.ErrorIs(t, err, authzone.ErrProvider)
	require.Nil(t, principal)
	require.Equal(t, int32(0), target.calls.Load())
}

func TestVerify_TimeoutIsProviderError(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	cfg := singleInstanceConfig(slow.URL, "")
	cfg.HTTPTimeout = 50 * time.Millisecond
	verifier, err := authzone.New(cfg)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), "opaque")

	require.ErrorIs(t, err, authzone.ErrProvider)
	require.NotErrorIs(t, err, authzone.ErrUnauthenticated)
}

func TestVerify_CanceledContextIsProviderError(t *testing.T) {
	s := newStand(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.verifier(t, false).Verify(ctx, "opaque")

	require.ErrorIs(t, err, authzone.ErrProvider)
	require.NotErrorIs(t, err, authzone.ErrUnauthenticated)
	require.Equal(t, int32(0), s.client.calls.Load())
}
