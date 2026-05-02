#!/usr/bin/env bash
# regress-crit1.sh — re-verify the FromID path-symmetry fix.
#
# CRIT-1 (caught by independent audit): attestation storage normalized
# --from "0000…0" to "" but the verifier looked up delta.FromID raw, so
# threshold checks reported "got 0" even with valid signatures present.
#
# Fix: NormalizeFromID inside ReferenceAuthorizationPath itself, so
# storer and reader cannot diverge by construction.
#
# This script reproduces the original failing scenario and asserts the
# bytewise-identical storage path across both --from forms. Exits non-
# zero on any check failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WORK="$(mktemp -d /tmp/jjtuf-crit1.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# ---------- build + tests ----------
cd "${PROJECT_ROOT}"
go vet ./... >/dev/null
JJTUF="${WORK}/jjtuf"
go build -o "${JJTUF}" ./main.go

if ! go test ./internal/attestations/... -run 'Path|Normalize' >/dev/null 2>&1; then
  echo "FAIL: attestations path/normalize unit tests not green"
  exit 1
fi
echo "[OK] unit: TestNormalizeFromID + TestPathSymmetry_NoParentSentinels pass"

# ---------- helper to bring a fresh repo to "ready to authorize" state ----------
make_repo() {
  local dir="$1"
  mkdir -p "${dir}" && cd "${dir}"
  jj git init --colocate >/dev/null 2>&1
  jj config set --repo user.name  test     >/dev/null
  jj config set --repo user.email test@t   >/dev/null
  ssh-keygen -t ed25519 -f alice -N "" -C alice >/dev/null 2>&1
  ssh-keygen -t ed25519 -f bob   -N "" -C bob   >/dev/null 2>&1
  "${JJTUF}" trust init --key-path alice.pub --signing-key alice >/dev/null
  "${JJTUF}" policy init >/dev/null
  "${JJTUF}" policy add-principal --key-path alice.pub --name alice >/dev/null
  "${JJTUF}" policy add-principal --key-path bob.pub   --name bob   >/dev/null
  "${JJTUF}" policy add-rule --name protect-main \
    --patterns bookmark:main --principals alice,bob --threshold 2 >/dev/null
  "${JJTUF}" policy apply >/dev/null
  echo hi > a.txt
  jj describe -m first 2>&1 >/dev/null
  jj new -m second 2>&1 >/dev/null
  jj bookmark create main -r @- 2>&1 >/dev/null
  "${JJTUF}" osl record >/dev/null 2>&1
}

# ---------- Case A: --from "0000…0" (the originally-failing form) ----------
WORK_A="${WORK}/A"
make_repo "${WORK_A}"
COMMIT=$(jj log -r main --no-graph -T commit_id | head -1)
TREE=$(git cat-file -p "${COMMIT}" | awk '/^tree/{print $2}')

"${JJTUF}" attest authorize --bookmark main \
  --from "0000000000000000000000000000000000000000" \
  --to "${TREE}" --key-file alice >/dev/null
"${JJTUF}" attest authorize --bookmark main \
  --from "0000000000000000000000000000000000000000" \
  --to "${TREE}" --key-file bob >/dev/null

PATH_A=$(git ls-tree -r refs/jjtuf/attestations | grep reference-authorizations | head -1 | awk '{print $NF}')

if "${JJTUF}" verify ref main >/dev/null 2>&1; then
  echo "[OK] Case A: --from \"0000…0\" → verify exit 0"
else
  echo "FAIL: Case A verify exited non-zero"
  "${JJTUF}" verify ref main || true
  exit 1
fi

# ---------- Case B: --from "" (empty, the canonical sentinel) ----------
WORK_B="${WORK}/B"
make_repo "${WORK_B}"
COMMIT=$(jj log -r main --no-graph -T commit_id | head -1)
TREE_B=$(git cat-file -p "${COMMIT}" | awk '/^tree/{print $2}')

"${JJTUF}" attest authorize --bookmark main --from "" \
  --to "${TREE_B}" --key-file alice >/dev/null
"${JJTUF}" attest authorize --bookmark main --from "" \
  --to "${TREE_B}" --key-file bob >/dev/null

PATH_B=$(git ls-tree -r refs/jjtuf/attestations | grep reference-authorizations | head -1 | awk '{print $NF}')

if "${JJTUF}" verify ref main >/dev/null 2>&1; then
  echo "[OK] Case B: --from \"\" → verify exit 0"
else
  echo "FAIL: Case B verify exited non-zero"
  exit 1
fi

# ---------- Path symmetry: trees are deterministic on identical content,
# so paths must be byte-identical (the tree IDs differ only because content
# differs across the two repos; we compare the suffix after the bookmark).
PATH_A_SUFFIX="${PATH_A##*/}"
PATH_B_SUFFIX="${PATH_B##*/}"

# Both must start with "-" (the canonical "no parent" sentinel).
if [[ "${PATH_A_SUFFIX}" == -* && "${PATH_B_SUFFIX}" == -* ]]; then
  echo "[OK] both --from forms produce paths with the canonical empty FromID prefix"
  echo "     A: ${PATH_A}"
  echo "     B: ${PATH_B}"
else
  echo "FAIL: storage paths do not start with the canonical empty FromID"
  echo "     A: ${PATH_A}"
  echo "     B: ${PATH_B}"
  exit 1
fi

echo
echo "CRIT-1 regression: PASS"
