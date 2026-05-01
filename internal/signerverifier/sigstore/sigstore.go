// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package sigstore implements keyless signing and verification using the
// Sigstore public-good instance (Fulcio CA + Rekor transparency log).
//
// Signing requires an OIDC identity token.  In CI/CD environments this is
// available via the SIGSTORE_ID_TOKEN environment variable or ambient GitHub
// Actions OIDC credentials.  The signed bundle (protobuf JSON) is returned
// from Sign and passed back into Verify for cryptographic validation.
//
// # Key storage
//
// A Sigstore identity is stored in policy metadata as an SSLibKey with:
//
//	keytype  = "sigstore"
//	scheme   = "fulcio"
//	keyval.identity = <email or sub from OIDC token>
//	keyval.issuer   = <OIDC issuer URL>
//
// The KeyID is the string "identity::issuer".
package sigstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

const (
	// KeyType identifies a Sigstore/Fulcio key in policy metadata.
	KeyType = "sigstore"

	// KeyScheme identifies the Fulcio-issued certificate scheme.
	KeyScheme = "fulcio"

	// EnvIDToken is the environment variable for an explicit OIDC token.
	EnvIDToken = "SIGSTORE_ID_TOKEN"

	// DefaultFulcioURL is the public-good Fulcio instance.
	DefaultFulcioURL = "https://fulcio.sigstore.dev"

	// DefaultRekorURL is the public-good Rekor instance.
	DefaultRekorURL = "https://rekor.sigstore.dev"
)

var (
	// ErrNoIDToken is returned when no OIDC token is available for signing.
	ErrNoIDToken = errors.New("no OIDC token: set SIGSTORE_ID_TOKEN or use ambient credentials")

	// ErrBundleInvalid is returned when the sigstore bundle cannot be parsed.
	ErrBundleInvalid = errors.New("invalid sigstore bundle")

	// ErrVerifyFailed is returned when bundle verification fails.
	ErrVerifyFailed = errors.New("sigstore verification failed")

	// ErrTrustedRoot is returned when the Sigstore TUF trusted root cannot be loaded.
	ErrTrustedRoot = errors.New("failed to load sigstore trusted root")
)

// Options configures a SignerVerifier.
type Options struct {
	FulcioURL string
	RekorURL  string
	IDToken   string
	// ExpectedIdentity is required for verification (the signer's email/SAN).
	ExpectedIdentity string
	// ExpectedIssuer is required for verification (e.g. "https://accounts.google.com").
	ExpectedIssuer string
}

// Option is a functional option for SignerVerifier.
type Option func(*Options)

// WithFulcioURL overrides the Fulcio endpoint.
func WithFulcioURL(url string) Option { return func(o *Options) { o.FulcioURL = url } }

// WithRekorURL overrides the Rekor endpoint.
func WithRekorURL(url string) Option { return func(o *Options) { o.RekorURL = url } }

// WithIDToken provides an explicit OIDC token for signing.
func WithIDToken(token string) Option { return func(o *Options) { o.IDToken = token } }

// SignerVerifier implements common.SignerVerifier using Sigstore keyless signing.
// The same struct is used both for signing (when an ID token is available) and
// for verification (when constructed from an SSLibKey storing identity+issuer).
type SignerVerifier struct {
	opts  Options
	ssKey *common.SSLibKey
}

// NewFromEnvironment creates a SignerVerifier for signing.  It reads the OIDC
// token from SIGSTORE_ID_TOKEN, falling back to GitHub Actions ambient
// credentials.
func NewFromEnvironment(opts ...Option) (*SignerVerifier, error) {
	token := os.Getenv(EnvIDToken)
	if token == "" {
		token = tryGitHubActionsToken()
	}
	if token == "" {
		return nil, ErrNoIDToken
	}
	return New(token, opts...)
}

// New creates a SignerVerifier for signing with the given OIDC token.
func New(idToken string, opts ...Option) (*SignerVerifier, error) {
	if idToken == "" {
		return nil, ErrNoIDToken
	}

	o := Options{
		FulcioURL: DefaultFulcioURL,
		RekorURL:  DefaultRekorURL,
		IDToken:   idToken,
	}
	for _, fn := range opts {
		fn(&o)
	}

	identity, issuer, err := parseTokenClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("parsing OIDC token: %w", err)
	}
	o.ExpectedIdentity = identity
	o.ExpectedIssuer = issuer

	keyID := fmt.Sprintf("%s::%s", identity, issuer)
	ssKey := &common.SSLibKey{
		KeyID:   keyID,
		KeyType: KeyType,
		Scheme:  KeyScheme,
		KeyVal: common.KeyVal{
			Identity: identity,
			Issuer:   issuer,
		},
	}

	return &SignerVerifier{opts: o, ssKey: ssKey}, nil
}

// NewVerifierFromSSLibKey creates a verify-only SignerVerifier from an SSLibKey.
// The key must have KeyType "sigstore" with Identity and Issuer populated.
func NewVerifierFromSSLibKey(key *common.SSLibKey) (*SignerVerifier, error) {
	if key.KeyType != KeyType {
		return nil, fmt.Errorf("unsupported key type %q for sigstore verifier", key.KeyType)
	}
	o := Options{
		FulcioURL:        DefaultFulcioURL,
		RekorURL:         DefaultRekorURL,
		ExpectedIdentity: key.KeyVal.Identity,
		ExpectedIssuer:   key.KeyVal.Issuer,
	}
	return &SignerVerifier{opts: o, ssKey: key}, nil
}

// Sign signs data using an ephemeral key obtained from Fulcio and records the
// event in Rekor.  It returns a serialised sigstore bundle (protobuf JSON)
// that can be stored and later passed to Verify.
func (s *SignerVerifier) Sign(data []byte) ([]byte, error) {
	if s.opts.IDToken == "" {
		return nil, ErrNoIDToken
	}

	content := &sign.PlainData{Data: data}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("creating ephemeral keypair: %w", err)
	}

	trustedMaterial, err := loadTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustedRoot, err)
	}

	bundleOpts := sign.BundleOptions{
		TrustedRoot: trustedMaterial,
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: s.opts.FulcioURL,
			Timeout: 30 * time.Second,
			Retries: 1,
		}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{
			IDToken: s.opts.IDToken,
		},
		TransparencyLogs: []sign.Transparency{
			sign.NewRekor(&sign.RekorOptions{
				BaseURL: s.opts.RekorURL,
				Timeout: 90 * time.Second,
				Retries: 1,
			}),
		},
	}

	signedBundle, err := sign.Bundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("signing with sigstore: %w", err)
	}

	bundleJSON, err := protojson.Marshal(signedBundle)
	if err != nil {
		return nil, fmt.Errorf("marshalling sigstore bundle: %w", err)
	}

	return bundleJSON, nil
}

// Verify verifies a sigstore bundle (protobuf JSON) against the expected
// identity and issuer stored in this verifier's SSLibKey.
func (s *SignerVerifier) Verify(data, sig []byte) error {
	if s.opts.ExpectedIdentity == "" || s.opts.ExpectedIssuer == "" {
		return fmt.Errorf("%w: verifier has no expected identity/issuer", ErrVerifyFailed)
	}

	pb := new(protobundle.Bundle)
	if err := protojson.Unmarshal(sig, pb); err != nil {
		return fmt.Errorf("%w: %v", ErrBundleInvalid, err)
	}

	b, err := bundle.NewBundle(pb)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBundleInvalid, err)
	}

	trustedMaterial, err := loadTrustedRoot()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustedRoot, err)
	}

	sev, err := verify.NewVerifier(trustedMaterial,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("creating sigstore verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(
		s.opts.ExpectedIssuer, "", s.opts.ExpectedIdentity, "")
	if err != nil {
		return fmt.Errorf("creating certificate identity constraint: %w", err)
	}

	_, err = sev.Verify(b, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(data)),
		verify.WithCertificateIdentity(certID),
	))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}

	return nil
}

// KeyID returns "identity::issuer" for the signing identity.
func (s *SignerVerifier) KeyID() string { return s.ssKey.KeyID }

// Public returns the SSLibKey for storage in policy metadata.
func (s *SignerVerifier) Public() *common.SSLibKey { return s.ssKey }

// loadTrustedRoot fetches the Sigstore public-good trusted root via TUF.
// Metadata is cached locally so subsequent calls are fast and offline-capable
// until the TUF cache expires.
func loadTrustedRoot() (root.TrustedMaterial, error) {
	opts := tuf.DefaultOptions()
	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("initialising TUF client: %w", err)
	}

	trustedRoot, err := root.GetTrustedRoot(client)
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}

	return trustedRoot, nil
}

// parseTokenClaims extracts the subject identity and issuer from a JWT payload.
func parseTokenClaims(token string) (identity, issuer string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("not a valid JWT (expected 3 parts, got %d)", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("base64-decoding JWT payload: %w", err)
	}

	var claims struct {
		Issuer        string `json:"iss"`
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("parsing JWT claims: %w", err)
	}

	if claims.Issuer == "" {
		return "", "", errors.New("JWT missing 'iss' claim")
	}

	if claims.Email != "" && claims.EmailVerified {
		identity = claims.Email
	} else {
		identity = claims.Subject
	}
	if identity == "" {
		return "", "", errors.New("JWT missing identity (sub/email) claim")
	}

	return identity, claims.Issuer, nil
}

// tryGitHubActionsToken attempts to retrieve an ambient OIDC token from
// GitHub Actions using the ACTIONS_ID_TOKEN_REQUEST_URL and
// ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables.
// Returns empty string if not in a GitHub Actions environment.
func tryGitHubActionsToken() string {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return ""
	}

	// Append the audience that Fulcio expects.
	if strings.Contains(requestURL, "?") {
		requestURL += "&audience=sigstore"
	} else {
		requestURL += "?audience=sigstore"
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}

	return result.Value
}
