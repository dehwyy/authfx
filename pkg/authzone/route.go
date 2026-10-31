package authzone

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func (v *Verifier) route(token string) []Instance {
	issuer, isJWT := jwtIssuer(token)
	if !isJWT {
		return v.instances
	}

	for _, instance := range v.instances {
		if issuer != "" && normalizeIssuer(instance.Issuer) == normalizeIssuer(issuer) {
			return []Instance{instance}
		}
	}

	return nil
}

func jwtIssuer(token string) (string, bool) {
	parts := strings.Split(
		token,
		".",
	)
	if len(parts) != 3 {
		return "", false
	}

	header := map[string]json.RawMessage{}
	if !decodeSegment(
		parts[0],
		&header,
	) {
		return "", false
	}

	payload := map[string]json.RawMessage{}
	if !decodeSegment(
		parts[1],
		&payload,
	) {
		return "", false
	}

	issuer := ""
	if raw, ok := payload["iss"]; ok {
		if err := json.Unmarshal(
			raw,
			&issuer,
		); err != nil {
			return "", true
		}
	}

	return issuer, true
}

func decodeSegment(
	segment string,
	target any,
) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(
		segment,
		"=",
	))
	if err != nil {
		return false
	}

	return json.Unmarshal(
		decoded,
		target,
	) == nil
}
