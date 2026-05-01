# jjtuf documentation

jjtuf is a TUF-based security layer for the [Jujutsu (jj)](https://github.com/jj-vcs/jj) version control system. It provides forge-agnostic, cryptographically-verifiable policy declaration, activity tracking, and policy enforcement for jj repositories.

It is inspired by [gittuf](https://github.com/gittuf/gittuf) — which provides the same model for Git — and adapts the design to jj's operation-based architecture.

## Quick navigation

| Document | What it covers |
|---|---|
| [Getting started](getting-started.md) | Install, build, initialize a protected repo, first verify |
| [Architecture](architecture.md) | Refs, OSL design, policy state, verification flow |
| [Features](features.md) | Full feature list mapped to commands |
| [CLI reference](cli-reference.md) | Every command, every flag, examples |
| [Cryptography](cryptography.md) | Key types, DSSE, key-ID computation, Sigstore |
| [Threat model](threat-model.md) | What jjtuf protects against, what it doesn't |
| [Comparison with gittuf](comparison-with-gittuf.md) | Side-by-side mapping and design differences |
| [Testing](testing.md) | Test strategy, audit history, how to run tests |
| [Development](development.md) | Code layout, contributing, adding new key/rule types |

## What you can do with jjtuf

In one sentence: declare who is allowed to move which jj bookmarks, prove that recorded operations comply, and detect tampering — without trusting the forge (GitHub, Gitea, etc.) to enforce any of it.

In a few sentences:

- Declare a **root of trust** signed by one or more principals.
- Define **policy rules** that protect bookmarks and file paths, optionally requiring threshold signatures from named principals.
- Append every jj operation to a signed **Operation State Log (OSL)** — the jj-native equivalent of gittuf's RSL.
- Pre-authorize multi-party bookmark moves with **reference-authorization attestations** (DSSE envelopes that accumulate signatures from multiple signers).
- Record forge **code-review approvals** as attestations.
- Verify that the recorded history complies with policy, with cryptographic enforcement of every signature.
- Enforce **global rules** like `block-force-pushes` that apply repository-wide.
- Sign keylessly via **Sigstore** (Fulcio + Rekor) using ambient OIDC credentials in CI.
- Synchronize all jjtuf metadata to a remote and re-verify after fetch.
- Auto-record OSL entries after every jj operation via a **post-operation hook**.

## Status

The cryptographic core, CLI surface, and end-to-end flow are implemented and tested. The project has been through two rounds of independent audit; both critical bugs the audits surfaced have regression tests pinning the fix at the lowest possible layer. See [Testing](testing.md#independent-audits) for the audit history.

## Project layout (top level)

```
jjtuf/
├── main.go                          entry point
├── docs/                            this directory
├── internal/
│   ├── attestations/                DSSE envelopes for ref-auth + code review
│   ├── cmd/                         cobra commands (one package per subcommand)
│   ├── jjinterface/                 jj operation log + view parsing
│   ├── osl/                         Operation State Log (signed, append-only)
│   ├── policy/                      policy state, verification engine
│   ├── signerverifier/              real crypto: ed25519 / ecdsa / rsa / ssh / gpg / sigstore
│   └── tuf/                         TUF metadata schemas (v0.1)
├── pkg/gitinterface/                thin wrapper over the git CLI (jj's storage backend)
└── experimental/
    ├── e2e/smoke.sh                 19-step end-to-end harness
    └── tamper-attestation/          Go helper that corrupts an attestation in-place
```

For the design rationale behind storing metadata as Git refs even though this is a jj tool, see [Architecture: Storage layer](architecture.md#storage-layer-why-git-refs).
