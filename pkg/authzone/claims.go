package authzone

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	metadataClaim    = "urn:zitadel:iam:user:metadata"
	projectRolesFmt  = "urn:zitadel:iam:org:project:%s:roles"
	introspectSuffix = "/oauth/v2/introspect"
)

type claims struct {
	active   bool
	issuer   string
	subject  string
	email    string
	picture  string
	exp      time.Time
	metadata map[string]string
	roles    []string
}

func parseClaims(
	body []byte,
	projectID string,
) (*claims, error) {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(
		body,
		&raw,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: invalid introspect body: %w",
			ErrProvider,
			err,
		)
	}

	parsed := &claims{}
	if err := readClaim(
		raw,
		"active",
		&parsed.active,
	); err != nil {
		return nil, err
	}

	if !parsed.active {
		return parsed, nil
	}

	if err := readStringClaims(
		raw,
		parsed,
	); err != nil {
		return nil, err
	}

	if err := readExp(
		raw,
		parsed,
	); err != nil {
		return nil, err
	}

	if err := readMetadata(
		raw,
		parsed,
	); err != nil {
		return nil, err
	}

	if err := readRoles(
		raw,
		parsed,
		projectID,
	); err != nil {
		return nil, err
	}

	return parsed, nil
}

func readClaim(
	raw map[string]json.RawMessage,
	key string,
	target any,
) error {
	value, ok := raw[key]
	if !ok {
		return nil
	}

	if err := json.Unmarshal(
		value,
		target,
	); err != nil {
		return fmt.Errorf(
			"%w: invalid %s claim: %w",
			ErrProvider,
			key,
			err,
		)
	}

	return nil
}

func readStringClaims(
	raw map[string]json.RawMessage,
	parsed *claims,
) error {
	targets := map[string]*string{
		"iss":     &parsed.issuer,
		"sub":     &parsed.subject,
		"email":   &parsed.email,
		"picture": &parsed.picture,
	}

	for key, target := range targets {
		if err := readClaim(
			raw,
			key,
			target,
		); err != nil {
			return err
		}
	}

	return nil
}

func readExp(
	raw map[string]json.RawMessage,
	parsed *claims,
) error {
	exp := float64(0)
	if err := readClaim(
		raw,
		"exp",
		&exp,
	); err != nil {
		return err
	}

	if exp > 0 && !math.IsInf(exp, 0) {
		parsed.exp = time.Unix(
			int64(exp),
			0,
		)
	}

	return nil
}

func readMetadata(
	raw map[string]json.RawMessage,
	parsed *claims,
) error {
	encoded := map[string]string{}
	if err := readClaim(
		raw,
		metadataClaim,
		&encoded,
	); err != nil {
		return err
	}

	parsed.metadata = make(
		map[string]string,
		len(encoded),
	)

	for key, value := range encoded {
		decoded, ok := decodeMetadataValue(value)
		if !ok {
			continue
		}

		parsed.metadata[key] = decoded
	}

	return nil
}

func decodeMetadataValue(value string) (string, bool) {
	trimmed := strings.TrimRight(
		value,
		"=",
	)

	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.RawStdEncoding,
	} {
		decoded, err := encoding.DecodeString(trimmed)
		if err == nil {
			return string(decoded), true
		}
	}

	return "", false
}

func readRoles(
	raw map[string]json.RawMessage,
	parsed *claims,
	projectID string,
) error {
	projectRoles := map[string]json.RawMessage{}
	if err := readClaim(
		raw,
		fmt.Sprintf(
			projectRolesFmt,
			projectID,
		),
		&projectRoles,
	); err != nil {
		return err
	}

	parsed.roles = make(
		[]string,
		0,
		len(projectRoles),
	)

	for role := range projectRoles {
		parsed.roles = append(
			parsed.roles,
			role,
		)
	}

	sort.Strings(parsed.roles)

	return nil
}
