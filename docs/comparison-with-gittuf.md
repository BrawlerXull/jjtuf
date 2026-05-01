# Comparison with gittuf

[gittuf](https://github.com/gittuf/gittuf) brings TUF-style security to Git. jjtuf brings the same model to [Jujutsu (jj)](https://github.com/jj-vcs/jj). The two projects share design DNA but diverge wherever jj's data model differs from Git's.

> **See also:** [Architecture](architecture.md) for jjtuf's internals.

## Why jjtuf is a separate tool

A common question: jj uses Git as a storage backend by default — why not just point gittuf at the colocated `.git/` directory?

Two reasons:

1. **gittuf's RSL (Reference State Log) records ref updates.** jj's primary unit of change is the **operation**, not the ref update. A single jj operation (`jj squash`, `jj rebase`, `jj op restore`) can move many bookmarks atomically and is undoable as a unit. Recording only the resulting ref updates loses that atomicity and the operation provenance jj makes available.
2. **jj has first-class concepts gittuf doesn't model.** Conflicts are state, not errors. Bookmarks are not Git refs (they have anonymous tracking, divergence semantics, etc.). Operations have parents and views. Modelling these in a Git-centric tool would either ignore the structure or wedge it in awkwardly.

jjtuf adopts gittuf's *trust model* (TUF root + targets, signed log, attestations) but builds its own activity log keyed on jj operations.

## Concept mapping

| gittuf concept | jjtuf equivalent | Notes |
|---|---|---|
| Reference (Git ref) | Bookmark (jj bookmark) | Bookmarks have no `refs/heads/` prefix; they're addressed as `bookmark:<name>` in policy patterns |
| RSL (Reference State Log) | OSL (Operation State Log) | Both are signed, append-only logs in custom Git refs |
| RSL entry | OperationEntry | gittuf records `(ref, oldOID, newOID)`; jjtuf records `(operationID, parentOps, viewDigest, []BookmarkDelta)` |
| RSL annotation | AnnotationEntry | Same shape: free-form notes attached to prior entries |
| Reference authorization | Reference authorization | Same DSSE envelope, same multi-signer accumulation. jjtuf path keys on `(bookmark, fromID, targetTreeID)`. |
| Code review approval | Code review approval | Same shape; system-scoped (`github`, `gerrit`, …) |
| Root of trust | Root of trust | Identical structure: principals + thresholds + global rules |
| Targets metadata | Targets metadata | Identical: per-namespace rules with principal lists and thresholds |
| Global rules | Global rules | Both support `block-force-pushes` and `threshold` |
| `gittuf rsl record` | `jjtuf osl record` | jjtuf is idempotent by `operationID`; safe to wire to a hook |
| `gittuf verify-ref` | `jjtuf verify ref` | Same verdict semantics |
| `gittuf trust init` | `jjtuf trust init` | Same |
| `gittuf policy add-rule` | `jjtuf policy add-rule` | Same |
| `gittuf attest authorize` | `jjtuf attest authorize` | Same; jjtuf adds `--sigstore` for keyless signing |
| pre-receive hook on a Git server | `jjtuf sync` post-fetch verification | Different mechanism (no jj forge protocol yet); see below |

## Differences in the trust + activity log

### Activity log keying

gittuf's RSL entry says: *"ref X moved from OID `a` to OID `b`."*

jjtuf's OSL entry says: *"jj operation `op-abc` happened (with parent operation `op-def` and view digest `vd-…`); as a side effect, bookmark X moved from `a` to `b`, bookmark Y moved from `c` to `d`, and bookmark Z hit a conflict state."*

This means an OSL entry is a strict superset of the equivalent RSL entries — same per-bookmark deltas, plus the operation context (id, parent ops, view digest, conflicts) jj provides natively.

### Idempotency

gittuf's `rsl record <ref>` is intentionally not idempotent: each invocation records the ref's current state, even if unchanged. The user controls when to record.

jjtuf's `osl record` is idempotent by `operationID`. Re-running it never duplicates an entry. This is a deliberate design choice so the command can be wired to a `post-operation` hook (`jjtuf hook install`) that fires after every jj action without producing log noise.

### Conflicts

jj surfaces merge conflicts as state in the working copy: a commit can be in a "conflict state" until resolved. The OSL records `BookmarkDelta.Conflict bool`, and the verifier flags conflict-state bookmarks as policy violations even if all other rules pass. gittuf has no equivalent because Git models conflicts as transient working-tree errors.

### Force-push detection

Both tools implement `block-force-pushes` the same way conceptually: walk back from the new commit, check whether the old commit is reachable, fail if not.

The implementation in jjtuf was the subject of [an audit finding](testing.md#crit-2-force-push-bypassed-without-targets): the global-rules block must run for every OSL entry regardless of whether a targets metadata file exists. The fix is in `internal/policy/verify.go`; the regression test pins it.

### Sigstore keyless signing

gittuf supports Sigstore via signed Git commits (verified through the cosign trusted root).

jjtuf supports Sigstore via DSSE-wrapped `sign.Bundle` envelopes from `sigstore-go`:
- `jjtuf trust add-sigstore-key` registers a `(identity, issuer)` pair as a principal.
- `jjtuf attest authorize --sigstore` consumes ambient OIDC (`SIGSTORE_ID_TOKEN` or GitHub Actions `ACTIONS_ID_TOKEN_REQUEST_*`), gets a Fulcio cert, signs, includes the result in Rekor, and stores the bundle as an envelope signature.
- Verification re-fetches the Sigstore trusted root (cached via TUF) and checks the bundle against the stored `(identity, issuer)`.

Functionally equivalent guarantees, different envelope format.

### Sync model

gittuf relies on Git server hooks (pre-receive on a forge) to enforce policy on push.

jjtuf's `sync` command is client-orchestrated:
- `--fetch-only` pulls jjtuf refs and re-verifies every bookmark with recorded entries; exits non-zero if any verification fails.
- `--push-only` pushes jjtuf refs.
- Default is fetch-then-push.

This is a deliberate trade-off: jj has no canonical forge protocol yet, so a server-side enforcement model would be premature. Client-side verification at fetch time still gives every peer the ability to reject a tampered or non-compliant remote, just at a different point in the workflow.

## Differences in storage

Both tools store metadata under custom refs in the underlying Git repository:

```
gittuf:        refs/gittuf/reference-state-log
               refs/gittuf/policy
               refs/gittuf/policy-staging
               refs/gittuf/attestations

jjtuf:         refs/jjtuf/operation-state-log
               refs/jjtuf/policy
               refs/jjtuf/policy-staging
               refs/jjtuf/attestations
```

Identical layout, different prefix. A repository can theoretically host both prefixes side by side (gittuf for the Git-centric workflow, jjtuf for the jj-centric workflow), but the two will not cross-verify — their activity logs record different things.

## What jjtuf intentionally borrows from gittuf

- DSSE envelope format with `payloadType` `application/vnd.jjtuf.*+json` (mirrors gittuf's `vnd.gittuf.*+json` namespace).
- TUF v0.1 metadata schemas (root, targets, principal, rule, global rule). See `internal/tuf/v01/`.
- The "principals carry one or more `SSLibKey` keys" model (one principal can rotate keys without changing identity).
- Key-ID computation via canonical-JSON SHA-256 (matches the SSLib / TUF reference).
- Two-phase policy editing (`policy-staging` → `policy apply`).

## What jjtuf does that gittuf does not (yet)

- Operation-level activity log with idempotent `record`.
- jj `post-operation` hook integration via `jjtuf hook install/uninstall/show`.
- First-class `--sigstore` flag on `attest authorize` / `attest approve` for keyless multi-signer flows in CI.
- Built-in `sigstore-go`-based bundle verification (no external `cosign verify` shell-out).

## What gittuf has that jjtuf does not (yet)

- Hooks-as-policy enforcement on the Git server side.
- Recovery / repair commands (e.g. RSL skip-verify modes for emergency unblocks).
- Sub-delegations in targets metadata (`delegations` block referencing a sub-targets file).
- Built-in `dev` mode and threshold-aware key-rotation tooling.

These are not architectural blockers — the metadata layer supports them — they just haven't been built yet. The signer/verifier infrastructure (`internal/signerverifier/`) and policy state machine are general enough to absorb them when the need arises.

## When to use which

| You want to protect a … | Use … |
|---|---|
| Pure Git repository | gittuf |
| jj repository (with or without a Git colocated backend) | jjtuf |
| jj repository where some collaborators only use git | gittuf, and treat jj users like any other Git client |
| jj repository where you want to record operation provenance, not just ref updates | jjtuf |
