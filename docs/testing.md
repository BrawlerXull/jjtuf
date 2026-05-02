# Testing

How jjtuf is tested, what the audits found, and how to run everything yourself.

> **See also:** [Architecture](architecture.md) for what's being tested, [Development](development.md) for adding new tests.

## Test layers

jjtuf has tests at four layers; each catches a different class of regression.

| Layer | Where | What it covers |
|---|---|---|
| Unit | per-package `*_test.go` | Pure-function correctness: key parsing, signature verification, path construction, JWT claim parsing |
| Integration | `internal/policy/verify_test.go`, `internal/policy/edgecase_test.go` | Real Git temp repos, real OSL entries, real attestations, real verification flow |
| Smoke (e2e) | `experimental/e2e/smoke.sh` | Real `jj` binary, real `jjtuf` binary, 19-step lifecycle |
| Independent audit | external Claude session, no shared context | Skeptical re-verification by an agent that does not trust the implementer's claims |

The audits caught two real bugs that none of the other layers caught. That is exactly the failure mode independent audits exist to detect — see [Independent audits](#independent-audits).

## Unit tests

Run with:

```bash
go test ./...
```

A spot tour of what's covered:

- **`internal/signerverifier/{ed25519,ecdsa,rsa}/`** — `TestSignAndVerify` (round-trip), `TestVerifyRejectsBadSignature` (tamper detection), `TestVerifyOnlyNoPrivateKey` (verify-only construction), `TestKeyIDDeterministic`.
- **`internal/signerverifier/dsse/`** — `TestSignatureIsOverPAENotRawPayload` pins that the DSSE pre-authentication encoding is signed, not the raw payload.
- **`internal/signerverifier/loader/`** — round-trip tests for PKCS#8, SEC1, PKCS#1, OpenSSH PEM, `authorized_keys`, PEM `PUBLIC KEY`.
- **`internal/signerverifier/sigstore/`** — JWT claim parsing for verified email / unverified email / sub-only; verifier construction; rejection of bundles missing identity; rejection of malformed JSON.
- **`internal/attestations/`** — `TestNormalizeFromID`, `TestPathSymmetry_NoParentSentinels` (regression for [CRIT-1](#crit-1-fromid-symmetry)), `TestPathDistinct_NonZeroFromID`.
- **`internal/jjinterface/`** — protobuf parsing tests using hand-crafted wire-format bytes (no dependency on generated proto code).
- **`internal/cmd/hook/`** — install/uninstall idempotency, both repo-local and global config paths.
- **`internal/osl/`** — entry serialization, parent-link walking, idempotency guard.

## Integration tests

`internal/policy/verify_test.go` and `internal/policy/edgecase_test.go` build real Git repositories in `t.TempDir()`, write real signed metadata blobs, and run the full verifier. There are 13 edge-case scenarios covering:

- Bookmark deletion without authorization → rejected
- Bookmark in conflict state → flagged
- Force-push (non-ancestor move) → blocked by global rule
- Force-push when targets file is **not** applied → still blocked (regression for [CRIT-2](#crit-2-force-push-bypassed-without-targets))
- Fast-forward update → allowed
- Multiple bookmarks moved in one operation, partial authorization → caught
- Full-history verification across three sequential updates
- Middle unauthorized entry in a multi-step history → caught
- Key not in policy → rejected
- Wildcard pattern `bookmark:release/*` → enforced
- Code-review-approval attestation flow → satisfied
- No-policy repo → passes (with global-rule-only enforcement)
- Duplicate-OSL prevention via `IsOperationIDRecorded`
- Annotation entries in the chain → don't break verification walk

Run only the integration suite:

```bash
go test ./internal/policy/... -v
```

## End-to-end smoke test

`experimental/e2e/smoke.sh` exercises the full lifecycle against a real `jj` binary:

```bash
go build -o /tmp/jjtuf ./main.go
JJTUF_BIN=/tmp/jjtuf experimental/e2e/smoke.sh
```

The 19 steps cover:

1. Sanity-check binary
2. Initialize jj repo (colocated)
3. Generate Ed25519 keypairs (alice, bob, eve)
4. `trust init` with signing key
5. `trust add-root-key`
6. `trust add-global-rule` (block-force-pushes)
7. `trust add-sigstore-key`
8. `trust inspect` — assert all three principals + global rule visible
9. `hook install` + `hook show` — assert hook line in `.jj/repo/config.toml`
10. `jj describe` + `jj bookmark create` — real commit and bookmark
11. `osl record` + ref check + idempotency
12. `attest authorize` × 2 (alice + bob, same envelope, no overwrite)
12b. Reject `attest authorize` without `--key-file` or `--sigstore`
13. `attest list` — assert visible
14. `verify ref main` — assert exit 0
15. Run all signerverifier unit tests as crypto smoke
16. OSL idempotency stress
17. Apply policy with `threshold=2` rule on `bookmark:main`
18. `verify ref main` with the rule active — assert exit 0 (2-of-2 satisfied)
19. Run `experimental/tamper-attestation` against the repo, then `verify ref` — assert exit non-zero (tamper rejected)

Pass criteria for the suite: **every step prints "OK"** and the final summary box appears.

## The tamper-attestation helper

`experimental/tamper-attestation/main.go` is a focused Go binary that:

1. Walks `refs/jjtuf/attestations` to find a reference-authorization blob (filtered by an optional path-substring argument).
2. Builds a forged DSSE envelope with valid base64 but cryptographically invalid signatures.
3. Rewrites the entire tree path from leaf to root, swapping the blob in place.
4. Updates the ref to a new tamper commit.

This is the test artifact that proves jjtuf catches storage-layer tampering, not just in-flight tampering. With it in the suite, `verify ref` is required to exit non-zero — meaning a Git-store attacker who manages to swap a blob still gets caught.

Use it directly:

```bash
go run ./experimental/tamper-attestation /path/to/repo
go run ./experimental/tamper-attestation /path/to/repo "main/"   # path filter
```

## Independent audits

Two rounds of independent audit, each in a fresh Claude session with no shared context. The auditor was instructed to be skeptical and verify claims by running real commands, not by trusting descriptions.

### Round 1

Verified the original feature claims:
- Build, vet, test pass
- All 29 enumerated features observed working or marked SKIP/PASS-via-help
- One critical bug surfaced (CRIT-1)

### Round 2

Verified the fix for CRIT-1 plus exercised previously-skipped features:
- CRIT-1 confirmed fixed end-to-end and at the unit layer
- Path symmetry property confirmed bytewise across `--from ""` and `--from "0000…0"`
- Tamper rejection confirmed (the tamper helper now drops verified signer count)
- Force-push detection confirmed broken in a configuration the prior round had not exercised — surfaced as **CRIT-2**

### Round 3

Verified the fix for CRIT-2:
- CRIT-2 confirmed fixed: force-push blocked even with no targets file applied
- Negative control: legitimate fast-forward still passes (no over-correction)
- CRIT-1 still fixed

### CRIT-1: FromID symmetry

**Auditor's finding:** A repository configured per the audit checklist (create bookmark, create 2-of-2 reference authorizations with `--from "0000…0"`, run `verify ref`) failed verification with `need 2 signatures from authorized principals, got 0` — despite the on-disk envelope clearly containing two valid signatures.

**Root cause:** The CLI normalized `--from "0000…0"` to `""` on the storage side, so the envelope landed at `reference-authorizations/main/-<tree>`. The verifier passed `delta.FromID` (the raw OSL value, which can be `""` or `"0000…0"` depending on the operation) without normalization, so the lookup hit `reference-authorizations/main/0000…0-<tree>`, which doesn't exist. Threshold math saw zero signatures.

**Fix:** Move `NormalizeFromID` inside `ReferenceAuthorizationPath` and `CodeReviewApprovalPath` themselves. Storer and reader both go through these functions, so they cannot diverge. Implementation in `internal/attestations/attestations.go`. Regression test: `internal/attestations/path_test.go::TestPathSymmetry_NoParentSentinels` proves `""`, `"   "`, `"0"`, `"00…0"` all collapse to one canonical path.

**Why earlier tests missed it:** The integration suite hand-crafted `BookmarkDelta{FromID: ""}` directly, so it never exercised the `"0000…0"` form jj actually emits. Lesson: when generating test data, exercise the shapes the production code path produces, not just the convenient ones.

### CRIT-2: force-push bypassed without targets

**Auditor's finding:** A repository with `block-force-pushes` set on the root of trust and **no** `policy init` (a perfectly valid configuration: global rules live in root metadata, not targets) passed verification cleanly even when `main` was moved to a non-ancestor commit. The global rule was silently ignored.

**Root cause:** `verifyEntry` in `internal/policy/verify.go` had an early return when `state.TargetsMetadata == nil` that ran *before* the global-rules loop. Any "global-rules only" deployment skipped the loop entirely.

**Fix:** Hoist the global-rules loop above the targets-nil short-circuit. Global rules apply regardless of whether a targets metadata file has been initialized. Regression test: `internal/policy/edgecase_test.go::TestForcePushBlocked_NoTargetsApplied` builds a policy ref containing only root metadata and asserts the global rule fires.

**Why earlier tests missed it:** The pre-existing `TestForcePushBlocked` always wrote both root and targets via `commitPolicy`, so the targets-nil branch was never taken. Same shape of mistake as CRIT-1: the test setup happened to dodge the broken code path.

### Audit-recommended improvements that did not require code changes

- Tamper helper picks blobs alphabetically — non-deterministic with multiple authorizations. **Addressed:** the helper now accepts an optional path-substring filter. Call sites in `e2e/smoke.sh` use single-authorization repos, so the issue did not manifest in practice, but the option closes the door for future multi-authorization tests.

- `trust init --key-path alice.pub --signing-key alice` registers the principal as `"root"` rather than honoring the file stem. **Acknowledged as a UX nit, not a security issue.** The initial principal carries the well-known name `root` by design; named principals are added afterward via `trust add-root-key --name`.

- OSL records a redundant entry when `jj bookmark set` is refused but jj still writes an op-log entry. **Acknowledged as fidelity vs. noise.** The OSL faithfully reflects jj's op log; verification iterates correctly and the right entry fires. Fix would belong at the recording layer (filter no-op deltas) if it ever becomes a real problem.

## Running everything

```bash
# Unit + integration
go vet ./...
go test ./...

# Integration only
go test ./internal/policy/... -v

# Single regression test
go test ./internal/policy/... -run TestForcePushBlocked_NoTargetsApplied -v
go test ./internal/attestations/... -run 'Path|Normalize' -v

# Build
go build -o /tmp/jjtuf ./main.go

# E2E smoke
JJTUF_BIN=/tmp/jjtuf experimental/e2e/smoke.sh

# Tamper-attestation helper
go run ./experimental/tamper-attestation /path/to/test/repo

# GPG integration tests (require system gpg)
go test -tags integration ./internal/signerverifier/gpg/...

# Audit harness (the same checks the independent audits ran)
experimental/audit/regress-crit1.sh        # FromID symmetry regression
experimental/audit/regress-crit2.sh        # force-push-without-targets regression
experimental/audit/feature-coverage.sh     # full 29-item feature audit
```

## Audit harness

The independent audits described below were originally driven by skeptical-prompt-driven Claude sessions. The same checks are now codified as runnable bash scripts under `experimental/audit/`, so anyone can re-verify jjtuf locally without spinning up a fresh agent.

| Script | Purpose |
|---|---|
| `feature-coverage.sh` | The full 29-item audit — root of trust, policy, OSL, attestations, crypto, verification, operational. Prints a PASS/FAIL/SKIP table; exits non-zero on any failure. |
| `regress-crit1.sh` | Pins the FromID path-symmetry fix: attestations stored with `--from "0000…0"` and `--from ""` resolve to the same envelope, and `verify ref` exits 0 in both forms. |
| `regress-crit2.sh` | Pins the global-rule-without-targets fix: `block-force-pushes` fires under a "trust init only" deployment, with a fast-forward negative control. |

See `experimental/audit/README.md` for usage details and the coverage map.

If you want to drive a *fresh* audit (an LLM session with no shared context), the pattern is:

1. Open a fresh Claude Code session with no prior context for this project.
2. Paste a self-contained prompt that:
   - States the project path
   - Lists the features to verify (with traceable command sequences — the scripts under `experimental/audit/` are a good starting point)
   - Demands evidence (quoted command output) for every claim
   - Tells the agent to be skeptical and not trust descriptions
3. Forward the report back; cross-check every PASS / FAIL against actual repository state.

The discipline of "don't trust the implementer; verify with `git ls-tree`, `git cat-file -p`, and `verify ref; echo $?`" is what surfaced both bugs.

## Coverage gaps to know about

Honest accounting of what is *not* exercised by the current test suite:

- **Sigstore end-to-end with real Fulcio.** The CLI surface and offline construction paths are tested. A full sign-verify-with-real-Fulcio cycle requires network and a working Sigstore public-good instance; not in the standard suite. Run manually with `SIGSTORE_ID_TOKEN=<jwt> jjtuf attest authorize --sigstore`.
- **`jjtuf cache populate / delete`.** The CLI is wired but not exercised in audit. Manual smoke recommended before relying on it.
- **`jjtuf verify mergeable` with complex policies.** Smoke-level only.
- **Sub-delegations.** Not implemented; no tests.
- **Performance / large-repo behavior.** No benchmarks. The OSL walk is `O(entries)` and `verify ref` is `O(entries × rules × signers)`; should be fine for repos with thousands of operations but unverified at million-scale.
