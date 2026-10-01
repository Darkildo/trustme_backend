#!/usr/bin/env bash
# Run every e2e_smoke scenario in sequence and print a summary.
#
# Usage:
#   bash examples/run_all.sh
#   bash examples/run_all.sh --message host:port
#   bash examples/run_all.sh --skip-slow      # skip the ~35s scenarios
#   bash examples/run_all.sh --only crash_before_ack,device_routing
#   bash examples/run_all.sh --include-known-red  # also run scenarios known to fail today
#
# Every scenario except probe_tofu needs the node static key (--node-key
# <hex32>, printed by the node at startup). KNOWN_RED_SCENARIOS lists
# scenarios expected to fail against the deployed build; it is empty while
# the deployment matches this tree.
#
# Exits with non-zero status if any non-known-red scenario fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FAST_SCENARIOS=(
  "online_roundtrip"
  "offline_then_online"
  "delivery_ack"
  "device_routing"
  "probe_config"
  "probe_tofu"
)
SLOW_SCENARIOS=(
  "no_dup_after_ack"
  "crash_before_ack"
  "quota_flood"
)
# Scenarios expected to fail against the current deployed server.
# Tracked here for visibility; not part of the default run.
KNOWN_RED_SCENARIOS=()

PASSTHROUGH=()
SKIP_SLOW=0
INCLUDE_KNOWN_RED=0
ONLY=""

is_known_red() {
  local needle="$1"
  for entry in "${KNOWN_RED_SCENARIOS[@]}"; do
    if [[ "$entry" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-slow)
      SKIP_SLOW=1
      shift
      ;;
    --include-known-red)
      INCLUDE_KNOWN_RED=1
      shift
      ;;
    --only)
      ONLY="$2"
      shift 2
      ;;
    --message|--node-key|--node-key-file|--metrics)
      PASSTHROUGH+=("$1" "$2")
      shift 2
      ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$ONLY" ]]; then
  IFS=',' read -r -a SCENARIOS <<<"$ONLY"
else
  SCENARIOS=("${FAST_SCENARIOS[@]}")
  if [[ "$SKIP_SLOW" -eq 0 ]]; then
    SCENARIOS+=("${SLOW_SCENARIOS[@]}")
  fi
  if [[ "$INCLUDE_KNOWN_RED" -eq 1 ]]; then
    SCENARIOS+=("${KNOWN_RED_SCENARIOS[@]}")
  fi
fi

LOG_DIR="$(mktemp -d -t e2e_smoke.XXXXXX)"
trap 'echo; echo "logs preserved at $LOG_DIR"' EXIT

echo "==> building e2e_smoke (release-free dev profile)"
( cd "$REPO_ROOT" && cargo build --example e2e_smoke ) || exit 1

declare -a RESULTS
declare -a DURATIONS
TOTAL_START=$SECONDS
PASS=0
FAIL=0
KNOWN_RED_FAIL=0
KNOWN_RED_UNEXPECTED_PASS=0

for scenario in "${SCENARIOS[@]}"; do
  printf '\n==> [%s] starting\n' "$scenario"
  log_file="$LOG_DIR/$scenario.log"
  start=$SECONDS
  if ( cd "$REPO_ROOT" && cargo run --quiet --example e2e_smoke -- \
        --scenario "$scenario" "${PASSTHROUGH[@]}" ) > "$log_file" 2>&1; then
    elapsed=$((SECONDS - start))
    if is_known_red "$scenario"; then
      RESULTS+=("XPASS $scenario  (${elapsed}s) [unexpected pass — server regression appears fixed]")
      KNOWN_RED_UNEXPECTED_PASS=$((KNOWN_RED_UNEXPECTED_PASS + 1))
      printf '    XPASS in %ds (known-red scenario passed — consider promoting it)\n' "$elapsed"
    else
      RESULTS+=("PASS  $scenario  (${elapsed}s)")
      PASS=$((PASS + 1))
      printf '    PASS in %ds\n' "$elapsed"
    fi
    DURATIONS+=("$elapsed")
    tail -n 4 "$log_file" | sed 's/^/    /'
  else
    elapsed=$((SECONDS - start))
    if is_known_red "$scenario"; then
      RESULTS+=("XFAIL $scenario  (${elapsed}s) [known regression] -> $log_file")
      KNOWN_RED_FAIL=$((KNOWN_RED_FAIL + 1))
      printf '    XFAIL in %ds (expected — known server-side regression)\n' "$elapsed"
    else
      RESULTS+=("FAIL  $scenario  (${elapsed}s) -> $log_file")
      FAIL=$((FAIL + 1))
      printf '    FAIL in %ds — full log: %s\n' "$elapsed" "$log_file"
    fi
    DURATIONS+=("$elapsed")
    tail -n 20 "$log_file" | sed 's/^/    /'
  fi
done

TOTAL=$((SECONDS - TOTAL_START))

echo
echo "============================================================"
printf 'e2e_smoke summary: %d passed, %d failed, total %ds\n' "$PASS" "$FAIL" "$TOTAL"
if [[ "$KNOWN_RED_FAIL" -gt 0 || "$KNOWN_RED_UNEXPECTED_PASS" -gt 0 ]]; then
  printf '  known-red: %d expected-fail, %d unexpected-pass\n' \
    "$KNOWN_RED_FAIL" "$KNOWN_RED_UNEXPECTED_PASS"
fi
echo "------------------------------------------------------------"
for line in "${RESULTS[@]}"; do
  echo "  $line"
done
echo "============================================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
