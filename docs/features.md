# Features

The full feature surface, grouped by capability. Each item links to the command(s) that implement it and the docs that explain it.

> **See also:** [CLI reference](cli-reference.md) for every flag, [Architecture](architecture.md) for how each feature works under the hood.

## Root of trust

| Feature | Command(s) | Notes |
|---|---|---|
| Initialize signed root metadata | `jjtuf trust init --key-path … --signing-key …` | Creates `refs/jjtuf/policy`. The signing key is optional but strongly recommended. |
| Add additional root principals | `jjtuf trust add-root-key --key-path … --name …` | Each principal can hold one or more keys. |
| Register a Sigstore identity as a principal | `jjtuf trust add-sigstore-key --identity … --issuer …` | Optional `--policy` also adds it as a policy signer. |
| Update root or policy threshold | `jjtuf trust update-threshold --root-threshold N --policy-threshold M` | Either flag can be used independently. |
| Add a global rule | `jjtuf trust add-global-rule --name … --type … --patterns …` | Types: `block-force-pushes`, `threshold`. |
| Remove a global rule | `jjtuf trust remove-global-rule --name …` | |
| Inspect current state | `jjtuf trust inspect` | Shows principals, thresholds, and global rules. |

## Per-namespace policy (targets metadata)

Two-phase: edits land in `refs/jjtuf/policy-staging` until `apply`.

| Feature | Command(s) |
|---|---|
| Initialize the rule file | `jjtuf policy init` |
| Add a principal usable by rules | `jjtuf policy add-principal --key-path … --name …` |
| Add a rule | `jjtuf policy add-rule --name … --patterns bookmark:main,file:src/* --principals alice,bob --threshold 2` |
| Update a rule | `jjtuf policy update-rule --name …` (supports new `--patterns`, `--principals`, `--threshold`) |
| Remove a rule | `jjtuf policy remove-rule --name …` |
| List rules and principals | `jjtuf policy list-rules` |
| Promote staged → active | `jjtuf policy apply` |

Pattern syntax:

- `bookmark:<name>` — exact bookmark match. `bookmark:*` matches every bookmark.
- `file:<path>` — file-path namespace (matches in `VerifyFileChanges`). Glob wildcards supported.

## Operation State Log (OSL)

| Feature | Command(s) | Notes |
|---|---|---|
| Record current jj operations | `jjtuf osl record` | Idempotent: re-running skips already-recorded operation IDs. Safe for hooks. |
| Display the log | `jjtuf osl log` | Shows entries newest-first with operation IDs and bookmark deltas. |
| Add a free-form annotation | `jjtuf osl annotate --target <entry-id>` | For human review trails. |
| Verify hash-chain integrity | `jjtuf osl verify-chain` | Walks parent links, detects rewrites. |

The OSL is signed at the Git-commit level (committer signature on each entry). See [Architecture: OSL](architecture.md#the-operation-state-log-osl).

## Attestations

DSSE envelopes that pre-authorize bookmark moves or record forge approvals.

| Feature | Command(s) | Notes |
|---|---|---|
| Pre-authorize a bookmark transition | `jjtuf attest authorize --bookmark … --to <treeID> [--from <commitID>] (--key-file … \| --sigstore)` | Multiple signers append to the same envelope; threshold rules see the cumulative signer set. |
| Record a code-review approval | `jjtuf attest approve --bookmark … --to … --system github --review-id 1234 (--key-file … \| --sigstore)` | One approval per `(bookmark, transition, system)` tuple. |
| List all attestations | `jjtuf attest list` | |

`--from` accepts either an empty string or any all-zeros sentinel for new bookmarks; both normalize to the same storage path. See [Cryptography: paths](cryptography.md#attestation-paths).

## Cryptography

| Feature | Where | Notes |
|---|---|---|
| Ed25519 sign/verify | `internal/signerverifier/ed25519` | Raw 32-byte public key, base64-encoded in `KeyVal.Public`. |
| ECDSA P-256 sign/verify | `internal/signerverifier/ecdsa` | DER-encoded sig, SHA-256. PKIX-encoded public key. |
| RSA-PSS-SHA256 sign/verify | `internal/signerverifier/rsa` | PKIX-encoded public key. |
| OpenSSH key parsing | `internal/signerverifier/ssh` | Parses OpenSSH PEM and `authorized_keys` formats; delegates to the underlying algorithm. |
| GPG (system binary) | `internal/signerverifier/gpg` | Detached ASCII-armor signatures via the system `gpg`. |
| Sigstore (Fulcio + Rekor) | `internal/signerverifier/sigstore` | Keyless signing with ambient OIDC; bundle stored as DSSE signature. |
| Unified key loader | `internal/signerverifier/loader` | One entry point for PKCS#8, SEC1, PKCS#1, OpenSSH PEM, `authorized_keys`, PEM `PUBLIC KEY`. |
| DSSE envelope sign + verify | `internal/signerverifier/dsse` | `Sign(SignerVerifier)` appends a signature; `VerifySignatures(keys)` returns the cryptographically-valid signer set. |

See [Cryptography](cryptography.md) for the wire formats and key-ID derivation.

## Verification

| Feature | Command(s) | Notes |
|---|---|---|
| Verify a single bookmark | `jjtuf verify ref <bookmark>` | Walks every OSL entry that touches the bookmark, applies global rules + per-namespace rules, returns aggregate verdict. |
| Check merge readiness | `jjtuf verify mergeable <feature> <target>` | Reports whether a fast-forward merge from feature → target would satisfy policy. |
| Force-push detection | (built into `verify ref`) | Implemented as a `block-force-pushes` global rule check on every OSL entry, regardless of whether targets metadata is applied. |
| Tampered-attestation rejection | (built into `verify ref`) | Signatures are re-verified against principal keys at every verify call, so an attacker who corrupts an envelope blob in the Git store is detected. |

## Operational

| Feature | Command(s) | Notes |
|---|---|---|
| Install jj `post-operation` hook | `jjtuf hook install [--global]` | Without `--global`: writes to `.jj/repo/config.toml` (repo-local). With `--global`: writes to `~/.config/jj/config.toml`. Idempotent. |
| Uninstall hook | `jjtuf hook uninstall [--global]` | |
| Show hook status | `jjtuf hook show` | Reports both repo-local and global state, plus jj version. |
| Push jjtuf metadata | `jjtuf sync --push-only [--remote …]` | Pushes the three jjtuf refs in one call. |
| Fetch + post-fetch verify | `jjtuf sync --fetch-only [--skip-verify]` | Runs `verify ref` for every bookmark with recorded entries; non-zero exit on violation. |
| Default sync (fetch then push) | `jjtuf sync` | Combines both. |
| Build verification cache | `jjtuf cache populate` | Speeds up repeat verifications. |
| Clear verification cache | `jjtuf cache delete` | |
| Print version | `jjtuf version` | |
| Generate shell completion | `jjtuf completion {bash,zsh,fish,powershell}` | Standard cobra completion. |

## CI / automation

| Feature | How |
|---|---|
| GitHub Actions keyless signing | Set `permissions: id-token: write`, then `jjtuf attest authorize --sigstore`. Reads `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` automatically. |
| Generic OIDC keyless signing | `SIGSTORE_ID_TOKEN=<jwt> jjtuf attest authorize --sigstore` |
| Threshold-of-two signers in different jobs | Each job calls `jjtuf attest authorize` with their own credentials; signatures accumulate on the same envelope. |
| Block PRs that violate policy | Run `jjtuf sync --fetch-only` in CI on PR branches; fail the job on non-zero exit. |

## Status flags by feature

| Feature | Status |
|---|---|
| All cryptographic backends | Implemented, real signatures, tamper-rejection unit-tested |
| Root of trust + global rules | Implemented and audit-verified |
| Two-phase policy with thresholds | Implemented and audit-verified |
| OSL with idempotent recording | Implemented |
| Reference + code-review attestations | Implemented |
| `--sigstore` flag on attest commands | Implemented |
| Force-push detection (with or without targets) | Implemented and audit-verified |
| Sync push | Implemented and audit-verified end-to-end |
| Sync fetch + post-fetch verify | Implemented |
| Verification cache | CLI present; not exercised in audit |
| TUF sub-delegations | Not yet implemented |
| Server-side / forge enforcement | Not yet implemented |
| Key-rotation tooling | Manual via `trust add-root-key` / `trust update-threshold` |

For audit findings (and how they were closed), see [Testing: independent audits](testing.md#independent-audits).
