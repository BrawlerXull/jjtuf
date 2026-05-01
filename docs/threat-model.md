# Threat model

What jjtuf actually defends against, what it doesn't, and the trust assumptions that hold the whole thing together. Read this before you wire jjtuf into a security-critical workflow.

> **See also:** [Architecture](architecture.md) for how the defenses are implemented, [Cryptography](cryptography.md) for the signature mechanics.

## The problem jjtuf solves

A team uses a forge (GitHub, Gitea, a self-hosted Git server) to coordinate work on a jj repository. The forge is **not** a trusted enforcement point:

- It can be compromised (admin account, supply chain on the forge software).
- It can mis-configure branch protection or silently disable it.
- It can accept a force-push that rewrites shared history.
- It has no insight into multi-party approval requirements that aren't expressed in its UI.

Without jjtuf, a peer cloning the repo has no cryptographic way to tell whether the history they pulled was approved by the right people, or whether the forge tampered with it before delivery.

jjtuf adds a parallel, cryptographically-verifiable channel that lives **inside the repository itself** as signed Git refs. Every peer can re-derive the verdict locally with no trust in the forge.

## Defended scenarios

### S1. Forge silently force-pushes a bookmark

**Scenario:** A compromised forge accepts (or originates) a force-push that moves `main` to a non-ancestor commit, rewriting history.

**Defense:** A `block-force-pushes` global rule on the root of trust catches this. After the next `jjtuf osl record + sync`, every peer's `jjtuf verify ref main` rejects the new entry.

**Caveat:** This only catches force-pushes that *get recorded into the OSL*. If the attacker manages to suppress the OSL update entirely, see S6.

### S2. Forge replaces a signature on a stored attestation

**Scenario:** An attacker with write access to the Git store swaps the bytes of a `reference-authorizations/main/...` blob, keeping the same `keyid` fields but inserting forged signatures.

**Defense:** `VerifySignatures` cryptographically re-validates each signature against the principal's public key at every verify call. Forged signatures don't verify, so they don't count toward thresholds. The threshold check fails.

This was confirmed end-to-end by the [tamper-attestation helper test](testing.md#tampered-attestation-rejection): swapping a blob drops verified signer count and `verify ref` exits non-zero.

### S3. Unauthorized signer attempts a bookmark move

**Scenario:** A developer not listed in the rule for `bookmark:main` signs a reference authorization with their own key and pushes it.

**Defense:** Verification only counts signatures from keys belonging to principals listed in the matching rule. An unauthorized signer's key won't be in any principal's key list, so their signature is ignored. The threshold check fails.

### S4. Compromised forge tampers with policy itself

**Scenario:** Attacker rewrites `refs/jjtuf/policy` to lower a threshold or remove a principal.

**Defense:** Root metadata is DSSE-signed by root principals at creation time. A peer that has independently fetched a previous root metadata blob (via `jjtuf sync` or any out-of-band means) can detect that the current root either lacks the expected signers or has had its threshold tampered with. The trust-on-first-use bootstrap is in scope; rotation policies are documented as a future direction.

**Caveat:** First-time clone trusts whatever root metadata the remote serves. Verifying that initial state requires an out-of-band exchange of the root principals' fingerprints (e.g. published in a README, signed by a corporate CA, or distributed via an org-level keyserver). jjtuf does not yet have a `--initial-root` flag for verifying first-fetch.

### S5. Unauthorized merge into a protected bookmark

**Scenario:** Someone tries to merge a feature branch into `release/*` without the required code-review approvals.

**Defense:** A rule like `--patterns "bookmark:release/*" --principals reviewers --threshold 2` requires two attestation signatures from the `reviewers` principal set. `jjtuf verify mergeable feature release/v1` reports whether the merge would satisfy policy *before* it is recorded.

### S6. Attacker suppresses OSL recording

**Scenario:** Attacker pushes a bookmark move without running `osl record`, hoping the OSL never reflects it.

**Defense in depth:**
1. `jjtuf hook install` wires the `post-operation` hook so `osl record` fires automatically on every jj action — making suppression require attacking the local jj configuration too.
2. `jjtuf sync --fetch-only` re-verifies every recorded bookmark; if the bookmark visible at the remote disagrees with the latest OSL entry, this is a divergence the verifier surfaces.
3. `jjtuf osl verify-chain` walks parent links and detects truncation or rewrite.

**Honest caveat:** A motivated attacker who controls both the forge and the local environment can in principle delay OSL recording. Defense in depth raises the bar; it does not eliminate this scenario. Mitigation patterns: schedule periodic `jjtuf sync` from a known-good machine and alert on policy violations.

### S7. Tampered attestation in transit

**Scenario:** Attacker on the network swaps an attestation blob in transit during `jjtuf sync`.

**Defense:** `git fetch` over HTTPS provides transport integrity. After fetch, `jjtuf sync` runs `verify ref` for every recorded bookmark; tampered attestations cause violations. So in-transit tampering surfaces as a verification failure on the next sync.

### S8. Sigstore-signed attestation forged offline

**Scenario:** Attacker tries to forge a Sigstore signature offline.

**Defense:** Sigstore signatures require:
1. A Fulcio-issued cert tied to a verified OIDC identity (forging this requires compromising the OIDC issuer or Fulcio).
2. A Rekor transparency-log inclusion proof (forging this leaves an entry in a public log that external monitoring will see).

The verifier requires both. A Sigstore-signed attestation is fundamentally a *public* claim; substitution leaves a tamper-evident trail.

## Out-of-scope: scenarios jjtuf does NOT defend against

These are real but jjtuf is the wrong layer to address them. Documenting them honestly so users don't assume protections that don't exist.

### N1. Compromised signing key

If a principal's private key is stolen, the attacker can produce arbitrarily many valid attestations. jjtuf has no built-in revocation today; the workflow is:

1. Run `jjtuf trust add-root-key` to add a replacement.
2. Use `jjtuf trust update-threshold` if the compromise affects threshold math.
3. Manually purge attestations signed by the compromised key. (No automated tooling for this yet.)

### N2. Insider with key access who acts maliciously

A principal with a valid key can produce attestations that pass verification. jjtuf enforces *who* can act, not *what* they can do with their authority. Use rules with `threshold > 1` from disjoint principal sets to limit the blast radius of a single compromised insider.

### N3. Compromised local build of jjtuf

If `jjtuf` itself is replaced with a malicious binary, that binary can lie about verification verdicts. Mitigations:

- Build from source from a known commit.
- Verify the binary using an independent jjtuf install (or `cosign verify` against future signed releases).
- Run verification in CI, not just locally.

### N4. Compromised jj binary

Same shape as N3, one layer down. jjtuf reads jj's operation log; a malicious jj could fabricate entries. Pin the jj version and verify it independently.

### N5. Workflow not actually using attestations

A team that adopts jjtuf but never adds a rule to `targets` metadata gets exactly the protections that come from global rules (force-push detection, repository-wide threshold) and nothing else. This is fine if those are all you want, but understand it: jjtuf is opt-in per-namespace, not opt-out.

### N6. Sigstore public-good infrastructure outage

Verifying Sigstore-signed attestations requires fetching the Sigstore trusted root via TUF. The library caches it locally so short outages are tolerable. Long outages or a hostile takeover of the public-good instance is a multi-organization concern outside any single tool's scope. For high-assurance settings, run a private Fulcio + Rekor and configure jjtuf to use it.

### N7. Replay across repositories

A signature on `(bookmark=main, from=A, to=tree-X)` is bound to that triple via the DSSE payload. It cannot be replayed onto a different bookmark or a different transition. **However**, jjtuf does not bind attestations to a specific repository identifier today: a stolen attestation envelope from repo A could in principle be presented as evidence in repo B if both repos happened to have the same bookmark name and the same `(fromID, treeID)` pair. The probability of collision is astronomically small for real codebases, but it is technically possible. A future version may add a repo-scoped salt to the payload.

### N8. Side channels

jjtuf does not protect against timing analysis, memory dumps of the signing process, or compromised hardware key stores. Use platform-appropriate key storage (YubiKey, TPM, OS keychain) — jjtuf's loader works with any private key in PKCS#8 / SEC1 / OpenSSH format that the OS gives it.

## Trust assumptions

For jjtuf's guarantees to hold, the following must be true:

1. The user's clone of the repository was either bootstrapped from a trusted source, or the root metadata's principal fingerprints were verified out-of-band on first fetch.
2. The user's local jjtuf binary is genuine (not replaced by a malicious build).
3. Private keys for principals are kept private. (Compromise is mitigated by threshold rules, not eliminated.)
4. The OIDC issuer used for Sigstore signing is itself trustworthy, and Fulcio + Rekor are functioning as designed. (See N6.)
5. SHA-256 and the underlying signature algorithms (Ed25519, ECDSA P-256, RSA-PSS) remain unbroken.
6. The local Git binary and storage are not compromised in ways that silently rewrite content. (jjtuf reads via the `git` CLI; a backdoored `git` could lie about object content.)

## Operational guidance

To get the most out of jjtuf:

- **Always set a `block-force-pushes` global rule.** It costs nothing and catches a large class of attacks.
- **Use threshold ≥ 2 for production bookmarks.** A single key compromise should not be sufficient to move shared history.
- **Wire `jjtuf hook install`** so OSL recording is automatic, then schedule `jjtuf sync` from CI to catch divergence.
- **Run `jjtuf verify ref` in CI on PRs** before merging. Treat verification failures as blocking.
- **Rotate root keys before they're compromised, not after.** Add a new principal, raise the threshold, then remove the old one.
- **Audit the principal list periodically.** Removed contributors should have their principals removed.

## Comparison: gittuf threat model

jjtuf inherits gittuf's threat model with one structural addition. Recording at the operation level rather than the ref-update level means an OSL entry carries strictly more information than the equivalent gittuf RSL entry — so any attack mitigated by RSL recording is also mitigated by OSL recording, plus jjtuf can additionally surface conflict-state bookmarks that gittuf cannot model. See [Comparison with gittuf](comparison-with-gittuf.md) for the full mapping.
