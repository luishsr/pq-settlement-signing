#!/usr/bin/env bash
# Two banks, one settlement instruction: sign it in each mode, verify it under each migration
# phase, then try the attacks the design is meant to stop. Needs cargo and jq.
# The script fails if any verification turns out differently than expected.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --quiet
bin=target/release/pq-settle
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
keys=$work/keys
phases=(accept-classical prefer-hybrid hybrid-required post-quantum-ready)

step() { printf '\n== %s\n' "$*"; }

# expect ACCEPTED|REJECTED <verify args...>: shows the verifier's answer, and stops on a surprise
# in either the verdict or the exit code (0 accepted, 1 rejected).
expect() {
  local want=$1 out status=0
  shift
  out=$("$bin" verify "$@") || status=$?
  echo "$out"
  local want_status=1
  [[ $want == ACCEPTED ]] && want_status=0
  [[ $out == "$want"* && $status == "$want_status" ]] ||
    { echo "!! expected $want (exit $want_status), got exit $status" >&2; exit 1; }
}

# tamper <jq filter> <name>: a modified copy of Bank A's hybrid-signed instruction.
tamper() { jq "$1" "$work/hybrid.json" > "$work/$2.json"; }

step "1. Each bank generates an Ed25519 and an ML-DSA-65 key pair"
"$bin" keygen --id bank-a --out-dir "$keys"
"$bin" keygen --id bank-b --out-dir "$keys"

step "2. Bank A signs the instruction in each mode"
for mode in classical hybrid post-quantum; do
  "$bin" sign --key "$keys/bank-a.key.json" --in examples/instruction.json \
    --mode "$mode" --out "$work/$mode.json"
done
for mode in classical hybrid post-quantum; do
  printf '%-18s %5d bytes as JSON (signatures hex-encoded)\n' "$mode.json" \
    "$(wc -c < "$work/$mode.json")"
done

step "3. Bank B verifies each one under each migration phase"
printf '%-14s' ""
printf ' %-19s' "${phases[@]}"
echo
# The migration policy: which mode each phase accepts (A) or rejects (R).
declare -A policy=([classical]="A A R R" [hybrid]="R A A A" [post-quantum]="R R R A")
for mode in classical hybrid post-quantum; do
  printf '%-14s' "$mode"
  row=""
  for phase in "${phases[@]}"; do
    result=$({ "$bin" verify --pub "$keys/bank-a.pub.json" --in "$work/$mode.json" \
      --phase "$phase" || true; } | awk 'NR == 1 { print $1 }')
    printf ' %-19s' "$result"
    row+="${result:0:1} "
  done
  echo
  [[ "${row% }" == "${policy[$mode]}" ]] ||
    { echo "!! $mode: expected ${policy[$mode]}, got ${row% }" >&2; exit 1; }
done

step "4. In full: a hybrid signature, and a classical one once hybrid is required"
expect ACCEPTED --pub "$keys/bank-a.pub.json" --in "$work/hybrid.json" --phase hybrid-required
expect REJECTED --pub "$keys/bank-a.pub.json" --in "$work/classical.json" --phase hybrid-required

step "5. Attacks on Bank A's hybrid-signed instruction"

echo "-- Tamper: raise the nominal from 1,000,000 to 9,000,000"
tamper '.instruction.nominal = 9000000' tampered
expect REJECTED --pub "$keys/bank-a.pub.json" --in "$work/tampered.json" --phase hybrid-required

echo "-- Strip: drop the ML-DSA half and present the Ed25519 half as classical,"
echo "   to a verifier still in prefer-hybrid (classical accepted)"
tamper '.signature.mode = "classical" | del(.signature.ml_dsa_65)' stripped
expect REJECTED --pub "$keys/bank-a.pub.json" --in "$work/stripped.json" --phase prefer-hybrid

echo "-- Downgrade: relabel the envelope as classical, keeping both signatures"
tamper '.signature.mode = "classical"' relabelled
expect REJECTED --pub "$keys/bank-a.pub.json" --in "$work/relabelled.json" --phase prefer-hybrid

echo "-- Smuggle: add a field the signature doesn't cover"
tamper '.instruction.memo = "pay to another account"' smuggled
expect REJECTED --pub "$keys/bank-a.pub.json" --in "$work/smuggled.json" --phase hybrid-required

echo "-- Impersonate: Bank B signs a changed instruction with its own keys and claims to be Bank A"
jq '.cash_amount_minor = 50000000' examples/instruction.json > "$work/cheaper.json"
"$bin" sign --key "$keys/bank-b.key.json" --in "$work/cheaper.json" --mode hybrid \
  --out "$work/forged.json" > /dev/null
jq '.signature.signer = "bank-a"' "$work/forged.json" > "$work/forged-as-a.json"
expect REJECTED --pub "$keys/bank-a.pub.json" --in "$work/forged-as-a.json" --phase hybrid-required

step "Every verification turned out as expected."
