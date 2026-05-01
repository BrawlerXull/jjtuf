# Getting started

This walks through installing jjtuf, initializing a protected repo, and running a full sign → record → verify cycle.

> **See also:** [Architecture](architecture.md) for what's happening under the hood, [CLI reference](cli-reference.md) for every flag.

## Prerequisites

- Go 1.21+ (tested with the toolchain pinned in `go.mod`)
- `jj` 0.39+ (`brew install jj` on macOS; see [jj's installation guide](https://github.com/jj-vcs/jj#installation))
- `ssh-keygen` (for generating Ed25519 signing keys)
- `git` (jj uses Git as its storage backend; jjtuf reads/writes refs on that backend)

Optional, for specific features:
- `gpg` (only if you want to use the GPG signer backend)
- A reachable remote (only for `jjtuf sync`)

## Build

From the repo root:

```bash
go build -o /usr/local/bin/jjtuf ./main.go
jjtuf version
```

Or run directly without installing:

```bash
go run ./main.go --help
```

## Hello-world: a protected repo in 10 commands

```bash
# 1. Init a colocated jj+git repo
mkdir myproj && cd myproj
jj git init --colocate

# 2. Generate a signing key (keep keys OUTSIDE the repo)
ssh-keygen -t ed25519 -f ~/.jjtuf-keys/alice -N "" -C alice@example.com

# 3. Initialize jjtuf — root of trust, signed by alice
jjtuf trust init \
  --key-path ~/.jjtuf-keys/alice.pub \
  --signing-key ~/.jjtuf-keys/alice

# 4. Block force-pushes globally
jjtuf trust add-global-rule \
  --name no-force-push \
  --type block-force-pushes \
  --patterns "bookmark:*"

# 5. Make a real commit and a main bookmark
echo "hello" > README.md
jj describe -m "first commit"
jj new -m "wip"
jj bookmark create main -r @-

# 6. Record the operation into the OSL
jjtuf osl record

# 7. Verify the bookmark complies with policy
jjtuf verify ref main
# → OK Bookmark "main": verification passed

# 8. Install the post-operation hook so OSL records are automatic
jjtuf hook install

# 9. Inspect the root of trust
jjtuf trust inspect

# 10. (Optional) Push jjtuf metadata to a remote
git remote add origin /path/to/origin.git
jjtuf sync --push-only
```

That's the minimum viable workflow. The next sections add multi-party signing and threshold rules.

## Multi-party threshold workflow

Two engineers (alice + bob) must both sign before `main` can move:

```bash
# Setup: alice already initialized trust as above. Add bob as a principal.
ssh-keygen -t ed25519 -f ~/.jjtuf-keys/bob -N "" -C bob@example.com

jjtuf policy init
jjtuf policy add-principal --key-path ~/.jjtuf-keys/alice.pub --name alice
jjtuf policy add-principal --key-path ~/.jjtuf-keys/bob.pub   --name bob
jjtuf policy add-rule \
  --name protect-main \
  --patterns bookmark:main \
  --principals alice,bob \
  --threshold 2
jjtuf policy apply
```

Now any change to `main` needs two reference-authorization signatures:

```bash
# Resolve the target tree for the bookmark's tip commit
COMMIT=$(jj log -r main --no-graph -T 'commit_id' | head -1)
TREE=$(git cat-file -p "$COMMIT" | awk '/^tree/ {print $2}')

# Alice authorizes
jjtuf attest authorize \
  --bookmark main --to "$TREE" \
  --key-file ~/.jjtuf-keys/alice

# Bob appends his signature to the same envelope (no overwrite)
jjtuf attest authorize \
  --bookmark main --to "$TREE" \
  --key-file ~/.jjtuf-keys/bob

jjtuf verify ref main
# → OK Bookmark "main": verification passed
```

If only alice has signed, verify fails:

```
FAIL Bookmark "main": verification failed
  - [main] rule "protect-main": verifier's key and threshold constraints not met:
      need 2 signatures from authorized principals, got 1
```

## Keyless signing in CI (Sigstore)

In a GitHub Actions workflow with `id-token: write` permission, no key file is needed:

```yaml
- name: Sigstore-sign a release authorization
  run: |
    jjtuf trust add-sigstore-key \
      --identity "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main" \
      --issuer   "https://token.actions.githubusercontent.com" \
      --name ci-bot --policy

    jjtuf attest authorize \
      --bookmark release --to "$TREE" \
      --sigstore
```

Sigstore-signed attestations are verified against the Sigstore public-good trusted root (Fulcio CA + Rekor transparency log) — same chain `cosign verify` uses. See [Cryptography: Sigstore](cryptography.md#sigstore-keyless-signing).

## Where things are stored

After this tutorial, your repo contains:

```
$ git for-each-ref refs/jjtuf/
… commit  refs/jjtuf/policy
… commit  refs/jjtuf/attestations
… commit  refs/jjtuf/operation-state-log
```

These refs live in the colocated Git store that backs your jj repo. They sync with `jjtuf sync` and are independently verifiable by anyone with the keys in the root of trust. See [Architecture: Storage layer](architecture.md#storage-layer-why-git-refs) for why.

## Next steps

- [Features](features.md) — the full feature list grouped by capability
- [Threat model](threat-model.md) — what jjtuf does and doesn't protect against
- [CLI reference](cli-reference.md) — every command and flag
