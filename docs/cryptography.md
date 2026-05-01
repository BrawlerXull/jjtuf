# Cryptography

How signatures are produced, stored, verified, and identified across jjtuf. Everything here is deterministic and auditable from the data on disk.

> **See also:** [Architecture](architecture.md) for where signed metadata lives, [Threat model](threat-model.md) for what these signatures actually attest to.

## Supported key types

| Algorithm | Scheme | `KeyType` | `Scheme` | Public-key encoding |
|---|---|---|---|---|
| Ed25519 | Ed25519 raw | `ed25519` | `ed25519` | base64 of the 32-byte raw public key |
| ECDSA P-256 | ECDSA-SHA256, DER-encoded `r,s` | `ecdsa` | `ecdsa-sha2-nistp256` | base64 of PKIX/SPKI DER |
| RSA | RSA-PSS-SHA256 | `rsa` | `rsassa-pss-sha256` | base64 of PKIX/SPKI DER |
| OpenSSH | parsed → underlying algorithm | `ssh` (storage), but verifies as the inner algorithm | `ssh` | as written by `ssh-keygen` |
| GPG | system `gpg`, ASCII-armored detached | `gpg` | `pgp` | OpenPGP fingerprint as key ID |
| Sigstore | Fulcio cert + Rekor inclusion | `sigstore` | `fulcio` | identity + issuer pair (no on-disk public key) |

The algorithm-specific packages live under `internal/signerverifier/<alg>/`. The `loader` package provides one entry point that dispatches by PEM block type / SSH wire format.

## The `SSLibKey` shape

Every public key is represented by the canonical Secure Systems Library structure:

```go
type SSLibKey struct {
    KeyID   string  // hex(SHA-256(canonical-JSON({keytype, keyval:{public}, scheme})))
    KeyType string  // "ed25519" | "ecdsa" | "rsa" | "ssh" | "gpg" | "sigstore"
    KeyVal  KeyVal
    Scheme  string  // see table above
}

type KeyVal struct {
    Public      string  // algorithm-specific (see table)
    Private     string  // never set in stored metadata
    Identity    string  // sigstore only
    Issuer      string  // sigstore only
    Certificate string  // reserved
}
```

This format is shared with gittuf and the upstream TUF / SSLib reference implementations, so jjtuf metadata can be inspected by anyone familiar with those tools.

## Key-ID derivation

Key IDs are deterministic. Given a public key, anyone can compute the same ID:

```
KeyID = hex( SHA256( canonical_JSON({
    "keytype": <KeyType>,
    "keyval":  {"public": <KeyVal.Public>},
    "scheme":  <Scheme>,
}) ) )
```

`canonical_JSON` here means: keys sorted lexicographically, no extraneous whitespace, no Unicode escapes for printable ASCII. The implementation lives in `internal/signerverifier/common/common.go::ComputeKeyID`.

Two consequences worth noting:

- The same Ed25519 key always produces the same key ID across machines and tools — interoperable with gittuf and TUF reference clients.
- Sigstore keys do **not** use this formula because their identity is `(identity, issuer)`, not a fixed public key. Their `KeyID` is the literal string `"<identity>::<issuer>"` (still deterministic, still globally unique).

## DSSE envelopes

All signed metadata in jjtuf is wrapped in [DSSE](https://github.com/secure-systems-lab/dsse) envelopes:

```json
{
  "payloadType": "https://jjtuf.dev/attestations/reference-authorization/v0.1",
  "payload":     "<base64 of the JSON payload>",
  "signatures": [
    {"keyid": "<hex KeyID>", "sig": "<base64 sig over PAE(payloadType, payload)>"},
    {"keyid": "…",            "sig": "…"}
  ]
}
```

`PAE` is the DSSE Pre-Authentication Encoding:

```
PAE(type, payload) = "DSSEv1" SP ASCII(len(type)) SP type SP ASCII(len(payload)) SP payload
```

This means the bytes that get signed include the `payloadType` URI, so an attacker can't reuse a signature on a different envelope type.

The implementation is in `internal/signerverifier/dsse/dsse.go`. Two operations:

- `env.Sign(signer SignerVerifier)` — appends a signature without disturbing prior signers (this is what makes multi-signer threshold flows work).
- `env.VerifySignatures(keys []*SSLibKey)` — for each signature, look up the key by `keyid`, verify the signature over `PAE(payloadType, payload)`, return the set of cryptographically-valid signer IDs.

A regression test (`TestSignatureIsOverPAENotRawPayload`) pins that signatures are computed over the PAE encoding rather than the raw payload, so swapping the `payloadType` invalidates the signature.

### Default verifier loader

`VerifySignatures` calls a package-level default loader to convert each `SSLibKey` into a `SignerVerifier`. To avoid an import cycle, this loader is **injected at startup** in `internal/cmd/root/root.go`:

```go
func init() {
    dsse.SetDefaultLoader(loader.LoadVerifierFromSSLibKey)
}
```

Tests that exercise DSSE verification independently must call the same wiring in their own `init()` — see `internal/policy/verify_test.go::init` for the pattern.

## Attestation paths

Reference authorizations and code-review approvals are stored under `refs/jjtuf/attestations` at deterministic paths so writers and readers can find each other:

```
reference-authorizations/<bookmark>/<NormalizeFromID(fromID)>-<targetTreeID>
code-review-approvals/<bookmark>/<NormalizeFromID(fromID)>-<targetTreeID>/<system>
```

`NormalizeFromID` collapses every "no parent" sentinel (empty string, whitespace-only, all-zeros hex of any length) to the canonical empty form. This guarantees that an attestation written with `--from "0000…0"` is found by a verifier that sees `delta.FromID = ""` — and vice versa.

Path construction goes through `internal/attestations/attestations.go`:

```go
func ReferenceAuthorizationPath(bookmarkName, fromID, toTreeID string) string {
    return path.Join(bookmarkName,
        fmt.Sprintf("%s-%s", NormalizeFromID(fromID), toTreeID))
}
```

Storer and reader both call this same function, so they cannot diverge by construction.

The audit story for why this matters is in [Testing: CRIT-1](testing.md#crit-1-fromid-symmetry).

## Sigstore keyless signing

The Sigstore backend (`internal/signerverifier/sigstore/`) wraps `sigstore-go` to provide keyless signing using ambient OIDC.

### Sign flow

```
1. Read OIDC token from SIGSTORE_ID_TOKEN, or fetch from
   GitHub Actions via ACTIONS_ID_TOKEN_REQUEST_URL+TOKEN.
2. Parse the JWT to extract identity and issuer claims:
     identity = email if email_verified, else sub
     issuer   = iss claim
3. Generate an ephemeral keypair via sign.NewEphemeralKeypair.
4. Fetch the Sigstore trusted root via TUF (cached locally).
5. Call sign.Bundle with:
     content        = sign.PlainData{Data: payload}
     CertProvider   = sign.NewFulcio(...)         (binds OIDC → cert)
     Transparency   = []sign.Transparency{Rekor}  (inclusion proof)
6. Marshal the resulting bundle as protobuf JSON.
7. Return the bundle bytes as the DSSE signature.
```

### Verify flow

```
1. protojson.Unmarshal the DSSE signature into a *protobundle.Bundle.
2. Wrap with bundle.NewBundle.
3. Fetch the Sigstore trusted root.
4. Construct verify.NewVerifier(trustedRoot,
       WithTransparencyLog(1),
       WithObserverTimestamps(1)).
5. Build a verify.NewShortCertificateIdentity from the
   stored (identity, issuer).
6. Call verifier.Verify(bundle, NewPolicy(
       WithArtifact(payload),
       WithCertificateIdentity(certID))).
```

This is functionally equivalent to `cosign verify` against the same bundle, with the added DSSE wrapper.

### What gets stored on disk

The DSSE envelope's `signatures[].sig` field contains the base64-encoded protobuf-JSON sigstore bundle. So a single attestation file can carry, for example, two Ed25519 signatures **and** one Sigstore signature side by side — verification iterates the principal's keys and dispatches each candidate signature to the appropriate algorithm.

## Tamper detection

Three layers, all checked at every `verify ref`:

1. **Cryptographic.** Any flipped bit in the payload, the `payloadType`, or a signature byte invalidates the corresponding signature. `VerifySignatures` returns only signers whose signatures actually verify, so tampering drops the signer count and threshold rules fail.
2. **Storage.** Git's content-addressed storage means swapping a blob changes its hash, which propagates up to the parent commit. An attacker has to either rewrite history (visible in `osl verify-chain`) or hope the verifier never re-runs.
3. **Inclusion.** Sigstore signatures must include a Rekor inclusion proof. The verifier rejects bundles without one. This means a Sigstore-signed attestation is *publicly* logged; an attacker silently substituting a forged bundle would also need to forge a transparency-log entry, which is detectable by external monitoring.

The audit confirmed this end-to-end: a manual swap of an attestation envelope blob in the Git store drops the verified signer count to zero (or one, depending on how many signatures were tampered) and threshold checks fail. See [Testing: the tamper-attestation helper](testing.md#the-tamper-attestation-helper).

## Why DSSE instead of inline JSON signatures or Sigstore-only?

- **Multi-algorithm.** A single envelope can carry signatures from different algorithms by different signers. An attestation might be signed by Alice's Ed25519 key, Bob's RSA key, and a CI bot's Sigstore identity — all in one envelope, all individually verifiable.
- **Stable signing surface.** PAE makes signatures domain-separated by `payloadType`, so adding new attestation types doesn't risk cross-type signature reuse.
- **Tooling overlap.** in-toto and the broader TUF/SSLib ecosystem use DSSE; jjtuf metadata is readable by their tools without translation.
