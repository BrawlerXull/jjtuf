// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

// makeJWT crafts a fake JWT (header.payload.signature) for parser tests.
// The signature is not cryptographically valid; parseTokenClaims only inspects
// the payload, so tests can use any string for the signature segment.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshalling claims: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".signature"
}

func TestParseTokenClaims_EmailVerified(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"iss":            "https://accounts.google.com",
		"sub":            "1234567890",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	identity, issuer, err := parseTokenClaims(tok)
	if err != nil {
		t.Fatalf("parseTokenClaims: %v", err)
	}
	if identity != "alice@example.com" {
		t.Errorf("identity = %q, want alice@example.com", identity)
	}
	if issuer != "https://accounts.google.com" {
		t.Errorf("issuer = %q, want https://accounts.google.com", issuer)
	}
}

func TestParseTokenClaims_EmailUnverified_FallsBackToSub(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"iss":            "https://accounts.google.com",
		"sub":            "1234567890",
		"email":          "bob@example.com",
		"email_verified": false,
	})

	identity, _, err := parseTokenClaims(tok)
	if err != nil {
		t.Fatalf("parseTokenClaims: %v", err)
	}
	if identity != "1234567890" {
		t.Errorf("identity = %q, want sub fallback 1234567890", identity)
	}
}

func TestParseTokenClaims_NoEmailUsesSub(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:org/repo:ref:refs/heads/main",
	})

	identity, issuer, err := parseTokenClaims(tok)
	if err != nil {
		t.Fatalf("parseTokenClaims: %v", err)
	}
	if identity != "repo:org/repo:ref:refs/heads/main" {
		t.Errorf("identity = %q", identity)
	}
	if issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("issuer = %q", issuer)
	}
}

func TestParseTokenClaims_MissingIssuer(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"sub": "1234567890",
	})

	_, _, err := parseTokenClaims(tok)
	if err == nil || !strings.Contains(err.Error(), "iss") {
		t.Errorf("expected missing-iss error, got %v", err)
	}
}

func TestParseTokenClaims_MissingIdentity(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"iss": "https://example.com",
	})

	_, _, err := parseTokenClaims(tok)
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("expected missing-identity error, got %v", err)
	}
}

func TestParseTokenClaims_NotAJWT(t *testing.T) {
	_, _, err := parseTokenClaims("not.a.jwt.has.too.many.parts")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}

func TestParseTokenClaims_BadBase64(t *testing.T) {
	_, _, err := parseTokenClaims("aaa.!!!not-base64!!!.bbb")
	if err == nil {
		t.Fatal("expected error for bad base64 payload")
	}
}

func TestNew_RejectsEmptyToken(t *testing.T) {
	_, err := New("")
	if !errors.Is(err, ErrNoIDToken) {
		t.Errorf("New(\"\") err = %v, want ErrNoIDToken", err)
	}
}

func TestNew_PopulatesSSLibKey(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"iss":            "https://accounts.google.com",
		"sub":            "1234567890",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	sv, err := New(tok)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub := sv.Public()
	if pub.KeyType != KeyType {
		t.Errorf("KeyType = %q, want %q", pub.KeyType, KeyType)
	}
	if pub.Scheme != KeyScheme {
		t.Errorf("Scheme = %q, want %q", pub.Scheme, KeyScheme)
	}
	if pub.KeyVal.Identity != "alice@example.com" {
		t.Errorf("Identity = %q", pub.KeyVal.Identity)
	}
	if pub.KeyVal.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer = %q", pub.KeyVal.Issuer)
	}
	want := "alice@example.com::https://accounts.google.com"
	if sv.KeyID() != want {
		t.Errorf("KeyID = %q, want %q", sv.KeyID(), want)
	}
}

func TestNewVerifierFromSSLibKey_HappyPath(t *testing.T) {
	key := &common.SSLibKey{
		KeyID:   "alice@example.com::https://accounts.google.com",
		KeyType: KeyType,
		Scheme:  KeyScheme,
		KeyVal: common.KeyVal{
			Identity: "alice@example.com",
			Issuer:   "https://accounts.google.com",
		},
	}

	sv, err := NewVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatalf("NewVerifierFromSSLibKey: %v", err)
	}
	if sv.opts.ExpectedIdentity != "alice@example.com" {
		t.Errorf("ExpectedIdentity = %q", sv.opts.ExpectedIdentity)
	}
	if sv.opts.ExpectedIssuer != "https://accounts.google.com" {
		t.Errorf("ExpectedIssuer = %q", sv.opts.ExpectedIssuer)
	}
	if sv.KeyID() != key.KeyID {
		t.Errorf("KeyID = %q, want %q", sv.KeyID(), key.KeyID)
	}
}

func TestNewVerifierFromSSLibKey_WrongKeyType(t *testing.T) {
	key := &common.SSLibKey{
		KeyType: "ed25519",
		KeyVal:  common.KeyVal{Public: "abc"},
	}
	_, err := NewVerifierFromSSLibKey(key)
	if err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("expected unsupported key type error, got %v", err)
	}
}

func TestVerify_NoIdentityConfigured(t *testing.T) {
	sv := &SignerVerifier{
		opts:  Options{},
		ssKey: &common.SSLibKey{KeyType: KeyType},
	}
	err := sv.Verify([]byte("data"), []byte("{}"))
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("Verify with no identity err = %v, want ErrVerifyFailed wrap", err)
	}
}

func TestVerify_BadBundleJSON(t *testing.T) {
	sv := &SignerVerifier{
		opts: Options{
			ExpectedIdentity: "alice@example.com",
			ExpectedIssuer:   "https://accounts.google.com",
		},
		ssKey: &common.SSLibKey{KeyType: KeyType},
	}
	err := sv.Verify([]byte("data"), []byte("not valid json"))
	if !errors.Is(err, ErrBundleInvalid) {
		t.Errorf("Verify with bad bundle err = %v, want ErrBundleInvalid wrap", err)
	}
}

func TestSign_NoIDToken(t *testing.T) {
	sv := &SignerVerifier{
		opts:  Options{},
		ssKey: &common.SSLibKey{KeyType: KeyType},
	}
	_, err := sv.Sign([]byte("data"))
	if !errors.Is(err, ErrNoIDToken) {
		t.Errorf("Sign without token err = %v, want ErrNoIDToken", err)
	}
}

func TestNewFromEnvironment_NoToken(t *testing.T) {
	t.Setenv(EnvIDToken, "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	_, err := NewFromEnvironment()
	if !errors.Is(err, ErrNoIDToken) {
		t.Errorf("NewFromEnvironment err = %v, want ErrNoIDToken", err)
	}
}
