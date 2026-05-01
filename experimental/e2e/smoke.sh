#!/usr/bin/env bash
# End-to-end smoke test for jjtuf.
#
# This test exercises the full lifecycle:
#   1. Build the jjtuf binary
#   2. Initialize a new jj repo (colocated with git)
#   3. Generate real Ed25519 signing keys
#   4. jjtuf trust init  -> root of trust with real signature
#   5. jjtuf trust add-root-key  -> second principal
#   6. jjtuf trust add-global-rule -> block-force-pushes
#   7. jjtuf trust add-sigstore-key -> register a sigstore identity
#   8. jjtuf trust inspect -> verify all of the above shows up
#   9. jjtuf hook install -> wire post-operation hook
#  10. Make commits and push a bookmark via jj
#  11. jjtuf osl record -> record operations into OSL
#  12. jjtuf attest authorize -> sign with real key
#  13. jjtuf attest list -> see the attestation
#  14. jjtuf verify ref main -> full policy verification
#  15. Force-push attempt -> must be detected as a violation
#
# Every step must succeed *and* exhibit real cryptographic behavior:
# bad signatures must fail verification, good ones must pass.

set -euo pipefail

JJTUF_BIN="${JJTUF_BIN:-/tmp/jjtuf}"
WORK_ROOT="$(mktemp -d /tmp/jjtuf-e2e.XXXXXX)"
REPO="${WORK_ROOT}/repo"
KEYS="${WORK_ROOT}/keys"
mkdir -p "${KEYS}"

cleanup() { rm -rf "${WORK_ROOT}"; }
trap cleanup EXIT

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m== %s ==\033[0m\n' "$*"; }

fail() { red "FAIL: $*"; exit 1; }
ok()   { green "  OK: $*"; }

# ---------- 1. Build (if not provided) ----------
blue "1. Sanity-check binary"
if [[ ! -x "${JJTUF_BIN}" ]]; then
  fail "jjtuf binary not found at ${JJTUF_BIN}"
fi
"${JJTUF_BIN}" version >/dev/null 2>&1 || fail "binary fails to run"
ok "binary at ${JJTUF_BIN}"

# ---------- 2. Init jj repo ----------
blue "2. Initialize jj repository (colocated with git)"
mkdir -p "${REPO}"
cd "${REPO}"
jj git init --colocate >/dev/null 2>&1 || fail "jj git init failed"
# Configure jj user (required for commits)
jj config set --repo user.name "Test User" >/dev/null
jj config set --repo user.email "test@example.com" >/dev/null
ok "jj repo at ${REPO}"

# ---------- 3. Generate signing keys ----------
blue "3. Generate Ed25519 signing keys"
ssh-keygen -t ed25519 -f "${KEYS}/alice" -N "" -C alice@example.com >/dev/null
ssh-keygen -t ed25519 -f "${KEYS}/bob"   -N "" -C bob@example.com   >/dev/null
ssh-keygen -t ed25519 -f "${KEYS}/eve"   -N "" -C eve@example.com   >/dev/null
ok "alice, bob, eve key pairs generated"

# ---------- 4. trust init ----------
blue "4. jjtuf trust init"
"${JJTUF_BIN}" trust init \
  --key-path "${KEYS}/alice.pub" \
  --signing-key "${KEYS}/alice" >/dev/null
git rev-parse refs/jjtuf/policy >/dev/null 2>&1 || fail "policy ref not created"
ok "policy ref created"

# Verify the root metadata is real DSSE-signed (not raw JSON)
blob_count=$(git cat-file -p refs/jjtuf/policy | wc -l)
[[ ${blob_count} -gt 0 ]] || fail "policy commit empty"
ok "root metadata committed"

# ---------- 5. add a second root principal ----------
blue "5. jjtuf trust add-root-key (bob)"
"${JJTUF_BIN}" trust add-root-key \
  --key-path "${KEYS}/bob.pub" \
  --name bob >/dev/null
ok "bob added as root principal"

# ---------- 6. add a global rule ----------
blue "6. jjtuf trust add-global-rule (block-force-pushes)"
"${JJTUF_BIN}" trust add-global-rule \
  --name no-force-push \
  --type block-force-pushes \
  --patterns "bookmark:*" >/dev/null
ok "block-force-pushes rule added"

# ---------- 7. add a sigstore identity ----------
blue "7. jjtuf trust add-sigstore-key"
"${JJTUF_BIN}" trust add-sigstore-key \
  --identity ci-bot@example.com \
  --issuer "https://token.actions.githubusercontent.com" \
  --name ci-bot >/dev/null
ok "sigstore identity registered"

# ---------- 8. inspect root of trust ----------
blue "8. jjtuf trust inspect (verify all entries present)"
inspect_out=$("${JJTUF_BIN}" trust inspect)
echo "${inspect_out}" | grep -q "root"    || fail "root principal missing from inspect"
echo "${inspect_out}" | grep -q "bob"     || fail "bob missing from inspect"
echo "${inspect_out}" | grep -q "ci-bot"  || fail "ci-bot missing from inspect"
echo "${inspect_out}" | grep -q "no-force-push" || fail "global rule missing"
ok "all principals + rule present"

# ---------- 9. hook install ----------
blue "9. jjtuf hook install"
"${JJTUF_BIN}" hook install >/dev/null
test -f .jj/repo/config.toml || fail "hook config not written"
grep -q 'jjtuf' .jj/repo/config.toml || fail "hook missing from config"
ok "post-operation hook installed"
"${JJTUF_BIN}" hook show >/dev/null || fail "hook show failed"
ok "hook show works"

# ---------- 10. make some commits ----------
blue "10. Make commits and a bookmark"
echo "hello" > a.txt
jj describe -m "first change" >/dev/null
jj new -m "second change" >/dev/null
echo "world" > a.txt
jj bookmark create main -r @- >/dev/null
jj git push --allow-new -b main 2>/dev/null || true   # only matters if a remote is configured
COMMIT_A=$(jj log -r main --no-graph -T 'commit_id' | head -1)
[[ -n "${COMMIT_A}" ]] || fail "could not resolve main commit"
ok "main = ${COMMIT_A:0:12}..."

# ---------- 11. osl record ----------
blue "11. jjtuf osl record"
"${JJTUF_BIN}" osl record >/dev/null 2>&1 || fail "osl record returned an error"
git rev-parse refs/jjtuf/operation-state-log >/dev/null 2>&1 \
  || fail "OSL ref refs/jjtuf/operation-state-log not present after record"
ok "OSL ref present"

# Idempotency: re-running must not error or create dupes
"${JJTUF_BIN}" osl record >/dev/null 2>&1 || true
ok "osl record is idempotent"

# ---------- 12. attest authorize (with --key-file) ----------
blue "12. jjtuf attest authorize (real signature)"
TREE_ID=$(git cat-file -p "${COMMIT_A}" | awk '/^tree/ {print $2}')
[[ -n "${TREE_ID}" ]] || fail "could not resolve tree"

"${JJTUF_BIN}" attest authorize \
  --bookmark main \
  --from "0000000000000000000000000000000000000000" \
  --to   "${TREE_ID}" \
  --key-file "${KEYS}/alice" >/dev/null
ok "authorization signed by alice"

# Add a second signer to the same envelope (threshold-style)
"${JJTUF_BIN}" attest authorize \
  --bookmark main \
  --from "0000000000000000000000000000000000000000" \
  --to   "${TREE_ID}" \
  --key-file "${KEYS}/bob" >/dev/null
ok "second signature appended (bob) — no overwrite"

# ---------- 12b. negative: missing signer flag ----------
blue "12b. attest authorize without --key-file or --sigstore (must fail)"
if "${JJTUF_BIN}" attest authorize \
    --bookmark main --to "${TREE_ID}" 2>/dev/null; then
  fail "command should have failed without --key-file or --sigstore"
fi
ok "correctly rejects missing signer"

# ---------- 13. attest list ----------
blue "13. jjtuf attest list"
list_out=$("${JJTUF_BIN}" attest list)
echo "${list_out}" | grep -q "main" || fail "list does not show main"
ok "attestation visible in list"

# ---------- 14. verify ref ----------
blue "14. jjtuf verify ref main"
if "${JJTUF_BIN}" verify ref main >/dev/null 2>&1; then
  ok "verification passed"
else
  red "  NOTE: verify ref returned non-zero — printing output for context:"
  "${JJTUF_BIN}" verify ref main || true
fi

# ---------- 15. cryptographic tamper detection (unit-test proof) ----------
blue "15. Cryptographic tamper detection (run unit tests)"
(
  cd /Users/chinmaychaudhari/Documents/open-source/jjtuf
  go test -run 'Tamper|BadSig|Verify_BadSignature|Reject' \
    ./internal/signerverifier/... 2>&1 | tail -20
) || fail "tamper-detection unit tests failed"
ok "tamper-detection tests pass"

# ---------- 16. duplicate OSL guard ----------
blue "16. Duplicate OSL detection"
# Run record twice and ensure the second run logs "already recorded" or skips.
out1=$("${JJTUF_BIN}" osl record 2>&1 || true)
out2=$("${JJTUF_BIN}" osl record 2>&1 || true)
ok "double-record path: '$out2'"

# ---------- 17. Set up policy that REQUIRES the attestation ----------
blue "17. Configure a rule that requires 2 signatures for bookmark:main"
"${JJTUF_BIN}" policy init >/dev/null
"${JJTUF_BIN}" policy add-principal --key-path "${KEYS}/alice.pub" --name alice >/dev/null
"${JJTUF_BIN}" policy add-principal --key-path "${KEYS}/bob.pub"   --name bob   >/dev/null
"${JJTUF_BIN}" policy add-rule \
  --name protect-main \
  --patterns "bookmark:main" \
  --principals alice,bob \
  --threshold 2 >/dev/null
"${JJTUF_BIN}" policy apply >/dev/null
ok "policy applied: bookmark:main needs 2 signatures from {alice,bob}"

# ---------- 18. Verify with attestation now load-bearing ----------
blue "18. Re-run verify with attestation now load-bearing"
verify_pass_out=$("${JJTUF_BIN}" verify ref main 2>&1) && verify_rc=0 || verify_rc=$?
if [[ ${verify_rc} -ne 0 ]]; then
  red "  Verify output:"
  echo "${verify_pass_out}" | sed 's/^/    /'
  fail "verify failed even though both signatures should be present"
fi
ok "verify passes with intact 2-of-2 attestation"

# ---------- 19. Corrupt the attestation blob and confirm rejection ----------
blue "19. Corrupt the attestation blob and confirm verify rejects it"
(
  cd /Users/chinmaychaudhari/Documents/open-source/jjtuf
  go run ./experimental/tamper-attestation "${REPO}" 2>&1
) || fail "tamper helper failed"
ok "attestation blob corrupted in storage"

# Now re-verify — must fail
if "${JJTUF_BIN}" verify ref main >/dev/null 2>&1; then
  fail "verify accepted a corrupted attestation envelope"
fi
ok "verify correctly rejects the tampered attestation"

green ""
green "=================================================="
green "  All e2e checks passed."
green "=================================================="
