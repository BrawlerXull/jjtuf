# Development

How to build, contribute, and extend jjtuf. If you're a new contributor, read [Architecture](architecture.md) first.

## Build environment

- Go 1.21+ (toolchain pinned in `go.mod`)
- `git` on PATH (jjtuf shells out for storage operations)
- `jj` 0.39+ (for end-to-end testing)
- `ssh-keygen`, `gpg` (optional, for testing those backends)

```bash
go build ./...                # build everything
go build -o /tmp/jjtuf .      # build the CLI
go vet ./...
go test ./...
```

## Code layout

The cardinal rule: **`internal/cmd/<sub>/` packages are thin**. Real logic lives under `internal/<domain>/`. The CLI packages glue cobra flags to domain calls.

```
main.go                              entry point — calls root.New().Execute()
internal/
├── cmd/                             one cobra package per subcommand
│   ├── root/                        wires DSSE default loader + stdout
│   ├── trust/                       root-of-trust commands
│   ├── policy/                      two-phase policy commands
│   ├── attest/                      authorize / approve / list
│   ├── osl/                         record / log / annotate / verify-chain
│   ├── verify/                      ref / mergeable
│   ├── sync/                        push/fetch + post-fetch verify
│   ├── hook/                        post-operation hook install/show/uninstall
│   └── cache/                       verification cache
├── attestations/                    DSSE storage, path normalization
├── jjinterface/                     jj op-store + view protobuf parsing
├── osl/                             entry types, append/walk, idempotency
├── policy/                          state, rules, verifier
├── signerverifier/
│   ├── common/                      SignerVerifier interface, SSLibKey
│   ├── ed25519/ ecdsa/ rsa/         per-algorithm packages
│   ├── ssh/                         OpenSSH parser → delegate to algorithm
│   ├── gpg/                         shells out to system gpg
│   ├── sigstore/                    Fulcio + Rekor via sigstore-go
│   ├── loader/                      unified key loader (PEM/SSH dispatch)
│   └── dsse/                        envelope sign + verify
├── tuf/v01/                         TUF metadata schemas
└── common/set/                      tiny set helper
pkg/
└── gitinterface/                    git CLI wrapper (executor, blob/tree/ref)
experimental/
├── e2e/smoke.sh                     19-step end-to-end harness
└── tamper-attestation/              storage-layer tamper helper
```

## Conventions

### Imports

Three groups separated by blank lines: stdlib, third-party, jjtuf-internal.

```go
import (
    "errors"
    "fmt"

    "github.com/spf13/cobra"

    "github.com/jjtuf/jjtuf/internal/attestations"
    "github.com/jjtuf/jjtuf/internal/jjinterface"
)
```

### Errors

- Wrap with `%w` if the caller might want to `errors.Is` the cause.
- Lowercase, no trailing punctuation.
- `fmt.Errorf("loading attestations: %w", err)` not `"Failed to load attestations: %v."`.
- Domain packages export sentinel errors when callers need to branch on them (`ErrAuthorizationNotFound`, `ErrOSLEntryNotFound`).

### Tests

- Unit tests live alongside source: `foo.go` → `foo_test.go`.
- Integration tests that need a real Git repo go in `internal/policy/verify_test.go` or `edgecase_test.go` and use the `policy_test` external test package.
- Use `t.TempDir()` for repo fixtures, never `/tmp/foo`.
- Generate keys in tests via `makeTestKey(t)` (already in `verify_test.go`).
- When asserting on signature behavior, exercise the **shape the production code path produces**, not just convenient fixtures. The integration suite missed two bugs because hand-crafted `BookmarkDelta{FromID: ""}` skipped real-world variants. See [Testing: lessons from audits](testing.md#independent-audits).

### Output

`cmd.Print*` writes to stdout (wired in `internal/cmd/root/root.go::New()` via `cmd.SetOut(os.Stdout)`). Errors and warnings go to stderr via `cmd.PrintErrf`. Pipelines should be able to capture meaningful command output without `2>&1`.

### No comments unless they explain *why*

Comments that restate what the code does are noise. Comments that record a non-obvious invariant, a workaround, or audit context are useful. Examples in the codebase:

```go
// Global rules live in root metadata and apply regardless of whether a
// targets/policy rule file has been initialized. Check them first so
// that a "global-rules only" deployment (e.g. block-force-pushes set
// at trust-init time, no policy apply) still enforces those rules.
```

That comment exists because an audit caught a bug where the loop was placed *after* an early-return. Without the comment, a future contributor refactoring `verifyEntry` could undo the fix.

## Adding a new key type

The bar is: **another `SignerVerifier` implementation that round-trips with no callers needing to special-case it.**

1. Create `internal/signerverifier/<alg>/<alg>.go` implementing the `common.SignerVerifier` interface:

   ```go
   type SignerVerifier interface {
       Sign(data []byte) ([]byte, error)
       Verify(data, sig []byte) error
       KeyID() string
       Public() *common.SSLibKey
   }
   ```

2. Add a constant to `common/common.go`:

   ```go
   const NewKeyType = "newalg"
   const NewSigningScheme = "newalg-sha256"
   ```

3. Add the dispatch case in `internal/signerverifier/loader/loader.go::LoadVerifierFromSSLibKey`:

   ```go
   case common.NewKeyType:
       return signewalg.NewVerifierFromSSLibKey(key)
   ```

4. If the key is a private-key file format, also wire it into `LoadSignerVerifierFromPEM` (the PEM block-type switch) and/or `newFromCryptoKey` (the crypto-package type switch).

5. Add tests under `internal/signerverifier/<alg>/<alg>_test.go`:
   - `TestSignAndVerify` — round trip on random bytes
   - `TestVerifyRejectsBadSignature` — flip a byte, assert verify fails
   - `TestKeyIDDeterministic` — same key → same key ID

The DSSE envelope path picks up the new type automatically because `VerifySignatures` calls the loader for each signature's `keyid`.

## Adding a new global rule type

1. Add a constant in `internal/tuf/types.go`:

   ```go
   const GlobalRuleNewType = "new-rule-type"
   ```

2. Update `tufv01.NewGlobalRule` to accept the new type.

3. Implement the check in `internal/policy/verify.go::verifyEntry`. The block-force-pushes precedent is the model:

   ```go
   if rules, exists := globalRules["new-rule-type"]; exists {
       for _, rule := range rules {
           // ... do the check, append to result.Violations on failure
       }
   }
   ```

4. Wire `--type new-rule-type` into `internal/cmd/trust/trust.go::addGlobalRuleCmd` if there are extra flags to validate.

5. Add an edge-case test to `internal/policy/edgecase_test.go`. **Crucially:** test both with and without a targets metadata file. CRIT-2 happened because the global-rule check was unreachable without targets; the same trap exists for any new global rule unless tested explicitly.

## Adding a new policy rule type (per-namespace, in targets)

This is more invasive than a global rule. You need to:

1. Add fields to `internal/tuf/v01/targets.go`'s `Rule` struct.
2. Update `tufv01.TargetsMetadata::AddRule` and `UpdateRule` to set them.
3. Implement the check in `internal/policy/verify.go::verifyEntry` after the per-rule signature check.
4. Add CLI flags to `internal/cmd/policy/policy.go::addRuleCmd` and `updateRuleCmd`.
5. Bump the schema version in `internal/tuf/v01/` (or fork to `v0.2/`) if the change is not backward-compatible.

## Adding a new attestation type

1. Define the payload schema in `internal/attestations/<type>.go`. Mirror the existing `authorization.go` / `approval.go`.
2. Define the storage path function in `internal/attestations/attestations.go`. **Use `NormalizeFromID`** if the path includes a from-ID.
3. Add `Set<Type>` / `Get<Type>` / `List<Type>s` methods on `*Attestations`.
4. Wire CLI commands in `internal/cmd/attest/`.
5. Add a regression test for path symmetry to `internal/attestations/path_test.go` if your type uses a from-ID.

## Style notes

- Follow `gofmt` (CI runs `go vet`). Format-on-save in your editor is recommended.
- Prefer concrete over abstract. New interfaces only when there is a second implementation in sight.
- Don't add backward-compat shims for things that haven't been released. The schema is `v0.1`; breaking changes are fine until we cut `v1.0`.
- Don't write tests against implementation details (private functions, log lines). Test through the public surface.

## Releasing

(Not yet automated.) Manual checklist:

1. Bump version in `internal/cmd/root/root.go::versionCmd` (currently `v0.1.0-dev`).
2. `go vet ./... && go test ./...` clean.
3. Run `experimental/e2e/smoke.sh` against the freshly-built binary.
4. Tag: `git tag v0.x.0` and push.
5. Build platform binaries (`GOOS=linux GOARCH=amd64 go build -o jjtuf-linux-amd64 .`, etc.).
6. (Future) sign release artifacts via `cosign sign-blob` and publish to GitHub Releases.

## Project decisions worth knowing

These are choices that have non-obvious consequences. Documented here so future contributors don't re-litigate them by accident.

- **`gitinterface` shells out to `git` instead of using `go-git`.** `go-git` has incomplete support for some packfile formats and refspec semantics; the `git` binary is universally available and battle-tested. Cost: every `gitinterface.Repository` operation is a subprocess. Acceptable at our scale.
- **DSSE default loader injected via `init()` in `cmd/root/`.** Avoids an import cycle (`dsse` → `loader` → algorithm-specific packages, while `loader` would need `dsse` directly otherwise). Tests that exercise DSSE outside the CLI must wire the loader themselves. See `internal/policy/verify_test.go::init`.
- **Path normalization inside the path-builder, not at call sites.** This is the architectural lesson from CRIT-1: spread normalization across many call sites and they will eventually drift. Centralize it in the function that constructs the path, and storer/reader cannot diverge by construction.
- **Global rules check runs before targets-nil short-circuit.** The architectural lesson from CRIT-2: an "early return on missing optional state" is a footgun if the optional state guards features that don't depend on it. Move the universal check above the conditional return.
- **Keys are stored as `SSLibKey`, not raw bytes.** Carries the algorithm, scheme, and computed key ID. Compatible with gittuf and TUF reference clients.
- **Two-phase policy editing.** Edits land in `policy-staging` until `apply`. Surface area for review before promotion. Same model gittuf uses.

## Where to ask questions

- File issues in the repository.
- For design discussion, prefer issues over PRs — describing a problem before patching it tends to surface alternatives.
- For security issues, please follow responsible-disclosure practices (issue or email, not a public PR).
