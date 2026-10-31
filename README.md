# authfx

Multi-instance Zitadel token introspection with staff/client zones. Package `pkg/authzone`.

- `authzone.New(Config)` builds a `Verifier` over one or more Zitadel instances, each bound to a zone (`ZoneStaff` or `ZoneClient`).
- `Verifier.Verify(ctx, token)` routes JWTs by `iss`, tries opaque tokens through the instances in order, introspects, and returns a `Principal`.
- A role is only ever counted inside its own zone: the staff instance keeps staff-class roles only, the client instance keeps client roles only. With `LegacyStaffInClient` the client instance additionally yields staff-class roles, marked by `Principal.Legacy()`.
- Staff-class roles are configured via `RoleSet` (exact names and prefixes); the library carries no project ids, domains or role names.
- Errors: `ErrUnauthenticated`, `ErrProvider` (network, 5xx, malformed body), `ErrInvalidConfig`.
- Optional positive and negative in-memory cache keyed by sha256 of the token.
