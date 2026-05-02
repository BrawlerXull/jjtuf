# Audit harness

Three runnable scripts that codify the independent-audit prompts that
caught CRIT-1 and CRIT-2 (see `docs/testing.md`). Run any of them
locally to re-verify jjtuf without spinning up a fresh agent session.

| Script | What it checks |
|---|---|
| `feature-coverage.sh` | The full 29-item feature audit (root of trust, policy, OSL, attestations, crypto, verification, operational) |
| `regress-crit1.sh` | FromID path-symmetry fix: attestations stored with `--from "0000…0"` and with `--from ""` resolve to the same envelope and `verify ref` exits 0 in both forms |
| `regress-crit2.sh` | `block-force-pushes` enforcement when only the root of trust is configured (no `policy apply`) — the bug the second audit round caught — plus a fast-forward negative control |

## Running

From the project root:

```bash
experimental/audit/regress-crit1.sh
experimental/audit/regress-crit2.sh
experimental/audit/feature-coverage.sh
```

Each script:
- Builds a fresh jjtuf binary in a temp dir (or honors `JJTUF_BIN=…`).
- Creates an isolated jj repo under `/tmp/jjtuf-*.XXXXXX`.
- Cleans up on exit.
- Exits non-zero on any check failure.

`feature-coverage.sh` prints a final table of 29 PASS/FAIL/SKIP rows.

## Requirements

- `go` (toolchain pinned in `go.mod`)
- `jj` 0.39+ on `PATH`
- `git`, `ssh-keygen`
- `python3` (only `feature-coverage.sh`, for JSON pretty-print of the
  stored DSSE envelope when checking signature count)

## Coverage map

| Audit item | Where it’s checked |
|---|---|
| Root of trust (1–5) | `feature-coverage.sh` §A |
| Per-namespace policy (6–10) | `feature-coverage.sh` §B |
| OSL (11–14) | `feature-coverage.sh` §C |
| Attestations (15–18) | `feature-coverage.sh` §D |
| Cryptography (19–22) | `feature-coverage.sh` §E |
| Verification (23–26) | `feature-coverage.sh` §F + `regress-crit1.sh` |
| Force-push (25) | `feature-coverage.sh` §F + `regress-crit2.sh` |
| Operational (27–29) | `feature-coverage.sh` §G |

The two regression scripts are deliberately narrow — they pin the exact
audit-discovered bugs rather than re-doing the broad coverage. Run them
in CI as cheap pre-commit guards; run `feature-coverage.sh` before
releases.
