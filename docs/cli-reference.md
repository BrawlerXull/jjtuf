# CLI reference

Full command tree with flags and one runnable example per command. Run `jjtuf <command> --help` to see the same output formatted by cobra.

> **See also:** [Getting started](getting-started.md) for a guided tour, [Features](features.md) for a capability map.

## Top-level

```
jjtuf [command]
```

| Subcommand | Purpose |
|---|---|
| `trust` | Manage the root of trust |
| `policy` | Manage per-namespace rules |
| `osl` | Operation State Log |
| `attest` | Reference authorizations and code-review approvals |
| `verify` | Check repository state against policy |
| `sync` | Push/fetch jjtuf refs to/from a remote |
| `hook` | Install the jj `post-operation` hook |
| `cache` | Manage the verification cache |
| `version` | Print build version |
| `completion` | Generate shell completions |

---

## `jjtuf trust`

### `trust init`

Create `refs/jjtuf/policy` with initial root metadata.

```
--key-path string       Public key for the initial root principal (SSH authorized_keys or PEM PUBLIC KEY)
--signing-key string    Private key used to sign the new root metadata (optional)
```

Example:

```bash
jjtuf trust init --key-path ~/.jjtuf-keys/alice.pub --signing-key ~/.jjtuf-keys/alice
```

### `trust add-root-key`

Add another principal to the root of trust.

```
--key-path string   Path to public key (required)
--name string       Principal name (defaults to the computed key ID)
```

### `trust add-sigstore-key`

Register an OIDC identity as a trusted principal. No private key needed locally — verification uses the Sigstore public-good infrastructure.

```
--identity string   OIDC subject (email or sub claim) (required)
--issuer   string   OIDC issuer URL (e.g. https://accounts.google.com) (required)
--name     string   Principal name (defaults to "<identity>::<issuer>")
--policy            Also add as a policy-signing principal
```

Example:

```bash
jjtuf trust add-sigstore-key \
  --identity ci-bot@example.com \
  --issuer   https://token.actions.githubusercontent.com \
  --name ci-bot --policy
```

### `trust add-global-rule`

Add a rule that applies repository-wide.

```
--name     string   Rule name (required)
--type     string   Rule type: "block-force-pushes" or "threshold" (default block-force-pushes)
--patterns strings  Namespace patterns (required), e.g. bookmark:main, bookmark:release/*
```

### `trust remove-global-rule`

```
--name string   Rule name to remove (required)
```

### `trust update-threshold`

Adjust signature thresholds. At least one of `--root-threshold` or `--policy-threshold` must be specified.

```
--root-threshold   int  New threshold for root metadata changes
--policy-threshold int  New threshold for primary rule file changes
```

### `trust inspect`

Print the active root of trust: schema version, thresholds, principals, and global rules. Output goes to stdout (pipe-friendly).

---

## `jjtuf policy`

Two-phase: edits go to `refs/jjtuf/policy-staging`; `apply` promotes them.

### `policy init`

Create an empty rule file in staging. Errors if a rule file already exists.

### `policy add-principal`

```
--key-path string   Path to SSH public key (required)
--name     string   Principal name (defaults to key ID)
```

### `policy add-rule`

```
--name       string    Rule name (required)
--patterns   strings   Namespace patterns (required), e.g. bookmark:main, file:src/*
--principals strings   Authorized principal names (required)
--threshold  int       Number of signatures required (default 1)
```

Example:

```bash
jjtuf policy add-rule \
  --name protect-release \
  --patterns "bookmark:release/*" \
  --principals alice,bob,carol \
  --threshold 2
```

### `policy update-rule`

Same flags as `add-rule`, but `--name` selects an existing rule. Any subset of the other flags can be supplied.

### `policy remove-rule`

```
--name string   Rule name to remove (required)
```

### `policy list-rules`

Print principals and rules from staging if present, otherwise from active.

### `policy apply`

Promote staging tree to `refs/jjtuf/policy`.

---

## `jjtuf osl`

### `osl record`

Read jj's operation log, compute bookmark deltas vs. parent operations, and append signed OSL entries. Idempotent — already-recorded operation IDs are skipped.

### `osl log`

Print recorded entries, newest first.

### `osl annotate`

```
--target string    Entry ID(s) being annotated (required, can repeat)
--message string   Annotation text (required)
```

### `osl verify-chain`

Walk parent links from the OSL tip back to the first entry. Detects rewrites and gaps.

---

## `jjtuf attest`

Provide exactly one of `--key-file` or `--sigstore`.

### `attest authorize`

Pre-authorize a bookmark transition. Multiple invocations append signatures to the same envelope.

```
--bookmark  string   Bookmark name (required)
--from      string   Current commit ID of the bookmark (empty or all-zeros for a new bookmark)
--to        string   Target tree ID after update (required)
--key-file  string   Path to private key (PKCS#8 / SEC1 / PKCS#1 / OpenSSH)
--sigstore           Use Sigstore keyless signing with ambient OIDC
```

Example:

```bash
COMMIT=$(jj log -r main --no-graph -T 'commit_id' | head -1)
TREE=$(git cat-file -p "$COMMIT" | awk '/^tree/{print $2}')

jjtuf attest authorize --bookmark main --to "$TREE" --key-file ~/.jjtuf-keys/alice
```

### `attest approve`

Record a forge code-review approval.

```
--bookmark  string   Bookmark name (required)
--from      string   Current commit ID (empty or all-zeros for a new bookmark)
--to        string   Target tree ID (required)
--system    string   Code review system (required), e.g. github, gerrit
--review-id string   System-specific review ID (e.g. PR number)
--key-file  string   Path to private key
--sigstore           Use Sigstore keyless signing
```

### `attest list`

Print all reference authorizations and code-review approvals stored under `refs/jjtuf/attestations`.

---

## `jjtuf verify`

### `verify ref <bookmark>`

Verify the specified bookmark against the current policy. Walks every OSL entry that touches it, runs global rules and per-namespace rules, aggregates verdicts. Exit non-zero on any violation.

Example output (passing):

```
OK Bookmark "main": verification passed (entry 9c9943379a96)
```

Failing:

```
FAIL Bookmark "main": verification failed (entry abdc9ea58709)
  - [main] global rule "no-force-push": force push blocked on main
Error: jjtuf policy verification failed
```

### `verify mergeable <feature> <target>`

Report whether merging `feature` into `target` would satisfy policy.

---

## `jjtuf sync`

```
--fetch-only           Only fetch remote metadata
--push-only            Only push local metadata
--remote string        Remote name (defaults to first configured remote)
--skip-verify          Skip post-fetch OSL verification (not recommended)
```

By default, fetches first, then pushes. After fetching, runs `verify ref` for every bookmark with recorded OSL entries; exits non-zero on any verification failure.

Example:

```bash
git remote add origin https://example.com/team/repo.git
jjtuf sync --push-only --remote origin
```

---

## `jjtuf hook`

### `hook install`

Write `post-operation = ["jjtuf", "osl", "record"]` to the jj config.

```
--global   Write to ~/.config/jj/config.toml instead of .jj/repo/config.toml
```

Idempotent: re-running does nothing if the entry is already present.

### `hook uninstall`

Remove the hook entry. Same `--global` semantics.

### `hook show`

Print install status (repo and global), plus the running jj version.

---

## `jjtuf cache`

### `cache populate`

Build a persistent verification cache for faster repeat verifications.

### `cache delete`

Clear the cache.

---

## `jjtuf version`

```
jjtuf v0.1.0-dev
```

---

## Exit codes

- `0` — success or "verification passed"
- `1` — generic failure (verification violation, missing flag, etc.)
- `2` — argument or usage error

## Common pitfalls

- **`--from` for new bookmarks.** Pass empty (`--from ""`) or any all-zeros hex string. Both normalize to the same path. See [Architecture: path normalization](architecture.md#path-normalization).
- **`--to` is the tree ID, not the commit ID.** Resolve with `git cat-file -p $COMMIT | awk '/^tree/{print $2}'`.
- **Storing keys inside the repo working copy.** `jj new "root()"` and other operations that check out an empty tree will delete files in the working copy. Keep signing keys in `~/.jjtuf-keys/` or similar, never in the repo.
- **`trust init --key-path alice.pub` registers the principal as `"root"`, not `"alice"`.** This is intentional today — the initial principal carries the well-known name `root`. Use `trust add-root-key --name alice` to register named principals afterward.
