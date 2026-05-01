# Architecture

This is jjtuf's design — what data lives where, how verification flows, and the rationale behind the trickier choices.

> **See also:** [Comparison with gittuf](comparison-with-gittuf.md) for how this maps to gittuf's design, [Cryptography](cryptography.md) for signature mechanics.

## High-level model

```
                ┌───────────────────────────────────────────────┐
                │                  jj workspace                 │
                │  ( .jj/  +  colocated .git/  in same dir )    │
                └───────────────────┬───────────────────────────┘
                                    │
              jj operations         │     jjtuf metadata
              (op log, views,       │     (signed refs)
               bookmarks)           │
                                    │
        ┌──────────────────┐        │        ┌─────────────────────────┐
        │ .jj/repo/op_store│        │        │ refs/jjtuf/policy       │
        │ .jj/repo/store   │        │        │ refs/jjtuf/operation-   │
        └──────────────────┘        │        │              state-log  │
                                    │        │ refs/jjtuf/attestations │
                                    │        └─────────────────────────┘
                                    │
                            jjtuf reads jj's
                            op log + emits
                            signed OSL entries
```

jjtuf reads jj's native operation log to derive bookmark deltas, then writes signed metadata to custom refs in the underlying Git store. Verification walks those refs and proves every recorded change complies with policy.

## Storage layer (why Git refs?)

jj uses Git as its default storage backend — when you run `jj git init --colocate`, jj creates a real `.git/` directory alongside `.jj/` and stores all commits, trees, and blobs there. jjtuf takes advantage of this by storing its own metadata as custom refs in that same Git store:

| Ref | Contents |
|---|---|
| `refs/jjtuf/policy` | Active policy: root metadata + (optional) targets metadata |
| `refs/jjtuf/policy-staging` | Staged policy edits before `jjtuf policy apply` |
| `refs/jjtuf/operation-state-log` | Append-only signed log of jj operations |
| `refs/jjtuf/attestations` | DSSE envelopes for ref authorizations and code-review approvals |

Why store as Git refs instead of files in `.jj/repo/`?

1. **Sync for free.** Git's push/fetch already replicates refs between hosts; `jjtuf sync` just delegates.
2. **Content-addressed and tamper-evident at the storage layer.** Any swap of a blob or tree changes the parent commit's hash.
3. **Same model as gittuf.** Auditors familiar with gittuf can read jjtuf storage with `git cat-file -p` directly.
4. **No new format to maintain.** Trees-of-blobs is well-understood and tooled.

This is why `pkg/gitinterface/` exists as a thin wrapper around the `git` CLI — it operates on jj's storage backend, not as a "git compatibility layer" for jj users. Users always interact with `jj` and `jjtuf` commands.

## The Operation State Log (OSL)

The OSL is the jj-native equivalent of gittuf's RSL. It is a chain of signed Git commits, where each commit is one **OSL entry** describing a jj operation and the bookmark deltas that operation produced.

### Entry types

```
type Entry interface {
    EntryType() string  // "operation" or "annotation"
}
```

- **OperationEntry** — wraps one jj operation. Records the `operationID`, `parentOperationIDs`, `viewDigest`, and a slice of `BookmarkDelta{Name, FromID, ToID, Conflict}`.
- **AnnotationEntry** — a free-form note attached to one or more prior entries (for human review trails).

The body of each entry lives in the Git commit message, in a structured key-value format readable with `git log refs/jjtuf/operation-state-log`. The commit's tree is empty; only the message carries data.

### How entries get appended

```
jj op log     (jj's native operation log, protobuf)
    │
    │  jjinterface.GetOperations
    ▼
[Operation, Operation, …]
    │
    │  ComputeBookmarkDeltas(parentView, childView)
    ▼
[BookmarkDelta{main, "abc", "def"}, …]
    │
    │  osl.NewOperationEntry + Commit
    ▼
refs/jjtuf/operation-state-log
```

The `IsOperationIDRecorded` guard in `internal/osl/osl.go` makes `jjtuf osl record` idempotent — re-running it never duplicates an entry, so it is safe to wire to a `post-operation` hook that fires after every jj action.

### Why per-operation, not per-ref-update like gittuf's RSL?

jj is **operation-based**, not commit-based. A single `jj squash` or `jj rebase` can move many bookmarks atomically, undo cleanly via `jj op restore`, and surface conflicts as first-class state. Recording at the operation level preserves that atomicity: one operation → one OSL entry → one signature → all bookmark deltas for that operation are accepted or rejected together.

## Policy state

A policy state at any point in history consists of two metadata files:

| File | Required? | Contents |
|---|---|---|
| `root` | Always | Root principals, root threshold, primary-rule-file principals + threshold, **global rules** |
| `targets` | Optional | Per-namespace rules (`bookmark:<name>`, `file:<path>`) with their own principal lists and thresholds |

Both are serialized as JSON, wrapped in DSSE envelopes, and stored as blobs under the policy commit's tree:

```
refs/jjtuf/policy
└── tree
    ├── root      (DSSE envelope)
    └── targets   (DSSE envelope, optional)
```

### Global rules

Global rules live in **root** metadata, not targets. They apply repository-wide regardless of whether a targets file has been initialized. The supported types today:

- **`block-force-pushes`** — rejects any bookmark transition where the new commit is not a descendant of the old one (i.e. a non-fast-forward).
- **`threshold`** — repository-wide minimum signature threshold.

This split matters for verification — see [Verification flow](#verification-flow).

### Two-phase apply

Policy edits land in `refs/jjtuf/policy-staging` first. `jjtuf policy apply` promotes the staging tree to `refs/jjtuf/policy`. This separates editing from activation so reviewers can inspect a staged change before it becomes load-bearing.

## Attestations

Attestations are DSSE envelopes that record additional context for actions, stored under `refs/jjtuf/attestations`.

### Reference authorizations

Pre-authorize a bookmark transition `(from-commit → target-tree)` for a named bookmark. Multiple signers append signatures to the *same* envelope so threshold rules can require N-of-M signers.

Storage path:

```
reference-authorizations/<bookmark>/<NormalizeFromID(fromID)>-<targetTreeID>
```

### Code-review approvals

Record a forge approval (GitHub PR review, Gerrit Code-Review+2, etc.) as a signed attestation, scoped to the same `(bookmark, fromID, targetTreeID, system)` tuple.

Storage path:

```
code-review-approvals/<bookmark>/<NormalizeFromID(fromID)>-<targetTreeID>/<system>
```

### Path normalization

`NormalizeFromID` collapses every "no parent" sentinel — empty string, whitespace, and any all-zeros hex string — to the canonical empty form. This guarantees that whatever the writer supplied (`""`, `"0000…0"`) and whatever the verifier sees from the OSL (`""`, `"0000…0"`) resolve to the same envelope.

This normalization sits inside the path-construction functions themselves:

```go
func ReferenceAuthorizationPath(bookmarkName, fromID, toTreeID string) string {
    return path.Join(bookmarkName,
        fmt.Sprintf("%s-%s", NormalizeFromID(fromID), toTreeID))
}
```

so storer and reader cannot diverge by construction. The audit trail for why this matters is in [Testing: independent audits](testing.md#independent-audits).

## Verification flow

`jjtuf verify ref <bookmark>` is the heart of the system. Here's what happens:

```
1. Load policy state from refs/jjtuf/policy
   ├─ Always parse root metadata
   └─ Parse targets metadata if present (optional)

2. Walk refs/jjtuf/operation-state-log entries that touch <bookmark>

3. For each entry:

   a. ── Global-rule check ────────────────────────
      Iterate root.GlobalRules. For block-force-pushes:
        - For each delta where delta.Name matches a rule pattern:
          - if delta.FromID and delta.ToID are non-empty:
            - if !KnowsCommit(toID, fromID):  → VIOLATION (force-push)

   b. ── Targets early-return ─────────────────────
      If targets metadata is absent, only global rules apply
      to this entry. Continue with the verdict from (a).

   c. ── Per-rule signature check ─────────────────
      For each rule whose patterns match "bookmark:<name>":
        - signerKeyIDs ← OSL entry's commit signer (if signed)
        - Load attestation envelope at
            reference-authorizations/<bookmark>/<from>-<treeID>
        - VerifySignatures(envelope, rule.principals.keys)
        - signerKeyIDs ← signerKeyIDs + verified attestation signers
        - if |unique signers ∩ rule.principals| < rule.threshold:
            → VIOLATION

4. Aggregate violations. Pass iff zero violations.
```

The two non-obvious bits:

- **Global rules run before targets-nil short-circuit.** A "trust init + add-global-rule" deployment with no `policy init` is a valid, supported configuration. See [Testing: CRIT-2](testing.md#crit-2-force-push-bypassed-without-targets).
- **Attestation lookup uses `delta.FromID`, normalized.** This is what `NormalizeFromID` is for. See [Testing: CRIT-1](testing.md#crit-1-fromid-symmetry).

## Putting it together: a typical request lifecycle

```
Engineer pushes a bookmark move
        │
        ▼
jj writes to .jj/repo/op_store and updates the bookmark
        │
        ▼  (post-operation hook fires)
jjtuf osl record
        │
        ├── Read jj's op log via jjinterface
        ├── Compute BookmarkDeltas between parent and child views
        ├── Append signed OSL entry to refs/jjtuf/operation-state-log
        └── (idempotent if this op was already recorded)
        │
        ▼
jjtuf sync --push-only       ← either manual or scheduled
        │
        └── git push origin refs/jjtuf/* (delegated to git)

──── on a peer ────

jjtuf sync --fetch-only
        │
        └── git fetch + verify every recorded bookmark in OSL
              against the freshly-fetched policy

If any verification fails → jjtuf sync exits non-zero.
```

## Code layout

```
internal/
├── attestations/
│   ├── attestations.go      DSSE storage paths, normalization, set/get
│   ├── path_test.go         path-symmetry regression
│   ├── authorization.go     reference-authorization payload schema
│   ├── approval.go          code-review-approval payload schema
│   └── …
├── cmd/                     one cobra package per CLI subcommand
│   ├── root/                root cmd (wires DSSE default loader at init)
│   ├── trust/               root-of-trust commands
│   ├── policy/              two-phase policy commands
│   ├── attest/              authorize / approve / list (--key-file or --sigstore)
│   ├── osl/                 record (idempotent) / log / annotate / verify-chain
│   ├── verify/              ref / mergeable
│   ├── sync/                fetch+push, post-fetch verification
│   ├── cache/               local verification cache
│   └── hook/                post-operation hook install/uninstall/show
├── jjinterface/             jj op-store + view protobuf parsing, BookmarkDelta computation
├── osl/                     entry types, append/walk, idempotency guard
├── policy/                  state, rule matching, verifier, signature checks
├── signerverifier/
│   ├── common/              SignerVerifier interface, SSLibKey, KeyID computation
│   ├── ed25519/             Ed25519 (raw)
│   ├── ecdsa/               ECDSA P-256, DER-encoded sig, SHA-256
│   ├── rsa/                 RSA-PSS-SHA256
│   ├── ssh/                 OpenSSH key parsing → delegate to algorithm package
│   ├── gpg/                 system gpg binary, fingerprint as key ID
│   ├── sigstore/            Fulcio cert + Rekor inclusion, protobuf JSON bundle
│   ├── loader/              unified key loader (PKCS#8 / SEC1 / PKCS#1 / OpenSSH / authorized_keys)
│   └── dsse/                envelope, Sign(SignerVerifier), VerifySignatures(keys, loader)
└── tuf/v01/                 TUF metadata schemas (root, targets, principal, rule, global rule)

pkg/
└── gitinterface/            thin wrapper over the git CLI (executor, blob/tree/ref helpers)
```

## What jjtuf does NOT do

- It does not replace jj's built-in operation log; it sits alongside.
- It does not gate jj operations themselves. The hook records *after* the fact; verification is what catches violations.
- It does not implement TUF's full delegation tree. Today there is one root and one optional targets file. Adding sub-delegations is a future direction.
- It does not handle key rotation policies. Adding/removing root principals is a manual action via `jjtuf trust`.

For a deeper treatment of trust assumptions, see the [Threat model](threat-model.md).
