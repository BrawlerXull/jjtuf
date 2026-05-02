#!/usr/bin/env bash
# regress-crit2.sh — re-verify the force-push-without-targets fix.
#
# CRIT-2 (caught by independent audit): block-force-pushes was silently
# bypassed when only global rules were configured (no policy targets
# file applied), because verifyEntry returned early on
# state.TargetsMetadata == nil before reaching the global-rules loop.
#
# Fix: hoist the global-rules loop above the targets-nil short-circuit.
# Global rules live in root metadata and apply regardless of targets.
#
# This script reproduces the original failing scenario plus a fast-
# forward negative control. Exits non-zero on any check failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WORK="$(mktemp -d /tmp/jjtuf-crit2.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# ---------- build + tests ----------
cd "${PROJECT_ROOT}"
go vet ./... >/dev/null
JJTUF="${WORK}/jjtuf"
go build -o "${JJTUF}" ./main.go

# Pin the regression test for this exact bug
if ! go test ./internal/policy/... -run TestForcePushBlocked_NoTargetsApplied >/dev/null 2>&1; then
  echo "FAIL: TestForcePushBlocked_NoTargetsApplied is missing or red"
  exit 1
fi
echo "[OK] unit: TestForcePushBlocked_NoTargetsApplied passes"

# ---------- helper: bring a repo to "trust + global rule, NO policy targets" ----------
init_root_only() {
  local dir="$1"
  mkdir -p "${dir}" && cd "${dir}"
  jj git init --colocate >/dev/null 2>&1
  jj config set --repo user.name  test    >/dev/null
  jj config set --repo user.email test@t  >/dev/null
  ssh-keygen -t ed25519 -f alice -N "" -C alice >/dev/null 2>&1
  "${JJTUF}" trust init --key-path alice.pub --signing-key alice >/dev/null
  "${JJTUF}" trust add-global-rule --name no-force-push \
    --type block-force-pushes --patterns "bookmark:*" >/dev/null
}

# ---------- Test 1: force-push must be REJECTED with no targets file ----------
WORK_FP="${WORK}/forcepush"
init_root_only "${WORK_FP}"

echo a > a.txt
jj describe -m commitA 2>&1 >/dev/null
jj new -m commitA-tip 2>&1 >/dev/null
jj bookmark create main -r @- 2>&1 >/dev/null
"${JJTUF}" osl record >/dev/null 2>&1

# Sanity: confirm policy ref has ONLY root metadata (no targets entry)
POL_TREE=$(git cat-file -p refs/jjtuf/policy | awk '/^tree/{print $2}')
ENTRIES=$(git ls-tree "${POL_TREE}" | wc -l | tr -d ' ')
if [[ "${ENTRIES}" -ne 1 ]]; then
  echo "FAIL: expected exactly 1 entry under refs/jjtuf/policy (root only); got ${ENTRIES}"
  git ls-tree "${POL_TREE}"
  exit 1
fi
echo "[OK] policy tree contains only root metadata (no targets entry)"

# Now force-push: sibling commit + bookmark set sideways
jj new "root()" -m commitB 2>&1 >/dev/null
jj bookmark set main -r @ --allow-backwards 2>&1 >/dev/null
"${JJTUF}" osl record >/dev/null 2>&1

verify_out=$("${JJTUF}" verify ref main 2>&1 || true)
verify_rc=$?
# Note: under set -e the rc above is captured via || true, so check the message
if echo "${verify_out}" | grep -qi "force push blocked"; then
  echo "[OK] force-push correctly REJECTED with global rule + no targets:"
  echo "     $(echo "${verify_out}" | grep -i 'force push blocked' | head -1)"
else
  echo "FAIL: force-push was NOT rejected. Verify output:"
  echo "${verify_out}" | sed 's/^/     /'
  exit 1
fi

# ---------- Test 2: legitimate FAST-FORWARD must still PASS ----------
# Negative control — make sure the fix didn't over-correct.
WORK_FF="${WORK}/fastforward"
init_root_only "${WORK_FF}"

echo a > a.txt
jj describe -m c1 2>&1 >/dev/null
jj new -m c2 2>&1 >/dev/null
jj bookmark create main -r @- 2>&1 >/dev/null
"${JJTUF}" osl record >/dev/null 2>&1

# Extend forward (descendant of current tip)
jj new -m c3 2>&1 >/dev/null
jj bookmark set main -r @- 2>&1 >/dev/null
"${JJTUF}" osl record >/dev/null 2>&1

if "${JJTUF}" verify ref main >/dev/null 2>&1; then
  echo "[OK] fast-forward update still PASSES under same global rule"
else
  echo "FAIL: fast-forward incorrectly rejected. Verify output:"
  "${JJTUF}" verify ref main || true
  exit 1
fi

echo
echo "CRIT-2 regression: PASS"
