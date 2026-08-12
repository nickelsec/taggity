#!/usr/bin/env bash
#
# Does `taggity draft` write the spec a person wrote by hand?
#
# Two cases from the corpus, chosen because they bound what the feature can do.
# Both need an API key, which is why this is a script you run rather than a test
# that runs in CI.
#
#   trytond   the fix deleted safe_eval, and its diff names everything a spec
#             needs. If drafting cannot match a hand-written spec here it will
#             not match one anywhere.
#
#   pycsw     the same construct lives in two files, and only one is reachable
#             from the description. The draft is EXPECTED to miss the second.
#             That is the documented limit, and --llm is what finds it.
#
# Usage:  scripts/drill.sh [trytond|pycsw|all]

set -uo pipefail
cd "$(dirname "$0")/.."

TAGGITY="${TAGGITY:-./bin/taggity}"

# Pin a provider and model so a drill is comparable run to run:
#   TAGGITY_DRILL_ARGS="--provider openrouter --model nvidia/nemotron-3-ultra-550b-a55b"
DRILL_ARGS="${TAGGITY_DRILL_ARGS:-}"

# Set to 1 to print the whole drafted spec, not just the fields checked.
SHOW="${TAGGITY_DRILL_SHOW:-}"

[ -x "$TAGGITY" ] || TAGGITY="go run ./cmd/taggity"

pass=0
fail=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
note() { printf '        %s\n' "$1"; }

# field <yaml> <key> — the last value for a key, so a code_any block reports the
# location that answered rather than the one listed first.
field() { grep -E "^\s*$2:" "$1" | tail -1 | sed "s/.*$2:[[:space:]]*//" | tr -d '\r'; }

drill_trytond() {
  echo
  echo "trytond GHSA-m9jj-5qvj-5fhx  (the fix deleted safe_eval)"

  local out; out=$(mktemp)
  if ! $TAGGITY draft $DRILL_ARGS \
        --repo https://github.com/tryton/trytond \
        --package trytond \
        --advisory GHSA-m9jj-5qvj-5fhx \
        "arbitrary command execution in ir.cron: callback arguments in
         trytond/ir/cron.py are expanded with safe_eval, which evaluates a
         Python expression, so anyone able to write a cron record runs code" \
        > "$out" 2>&1; then
    bad "draft failed"; sed 's/^/        /' "$out"; rm -f "$out"; return
  fi

  local file symbol calls indicates
  file=$(field "$out" file)
  symbol=$(field "$out" symbol)
  calls=$(field "$out" calls)
  indicates=$(field "$out" indicates)

  note "file:      $file"
  note "symbol:    $symbol"
  note "calls:     $calls"
  note "indicates: ${indicates:-vulnerable (default)}"

  [ "$file" = "trytond/ir/cron.py" ] \
    && ok "named the file" || bad "file is $file, want trytond/ir/cron.py"

  # The class qualifier is what makes this unambiguous, and _callback alone is
  # a defensible answer, so accept either and say which.
  case "$symbol" in
    Cron._callback) ok "named the symbol, qualified" ;;
    _callback)      ok "named the symbol (unqualified; the corpus spec qualifies it)" ;;
    *)              bad "symbol is $symbol, want Cron._callback" ;;
  esac

  [ "$calls" = "safe_eval" ] \
    && ok "named the token the fix deleted" \
    || bad "calls is $calls, want safe_eval"

  # The hard one. safe_eval is gone after the fix, so a match means the bug.
  # indicates: fixed here inverts every verdict in a report.
  case "$indicates" in
    ""|vulnerable) ok "polarity: a match is the bug" ;;
    *)             bad "polarity is '$indicates', want vulnerable: safe_eval is
                        absent after the fix, so a match means the bug is there" ;;
  esac

  [ -n "$SHOW" ] && { echo; sed 's/^/        /' "$out"; }
  rm -f "$out"
}

drill_pycsw() {
  echo
  echo "pycsw GHSA-hg4c-rgvm-964g  (the same code lives in two files)"

  local out; out=$(mktemp)
  if ! $TAGGITY draft $DRILL_ARGS \
        --repo https://github.com/geopython/pycsw \
        --package pycsw \
        --advisory GHSA-hg4c-rgvm-964g \
        "SQL injection: getrecords in pycsw/server.py passes a caller-supplied
         CQL_TEXT constraint through _cql_update_queryables_mappings straight
         into the WHERE clause" \
        > "$out" 2>&1; then
    bad "draft failed"; sed 's/^/        /' "$out"; rm -f "$out"; return
  fi

  local file calls
  file=$(field "$out" file)
  calls=$(field "$out" calls)
  note "file:  $file"
  note "calls: $calls"

  grep -q "pycsw/server.py" "$out" \
    && ok "named the file the description mentions" \
    || bad "did not name pycsw/server.py"

  grep -q "_cql_update_queryables_mappings" "$out" \
    && ok "named the unsafe call" \
    || bad "did not name _cql_update_queryables_mappings"

  # The point of this drill. The 2.x line moved CSW handling into csw2.py,
  # which the description never mentions, so no prompt recovers it. A draft
  # that finds it anyway is a bonus, not the bar.
  if grep -q "csw2.py" "$out"; then
    note "also found pycsw/ogc/csw/csw2.py, which the description did not name"
  else
    ok "missed csw2.py, as documented: a description-derived spec covers only
        what the description mentions. --llm is what finds the rest"
  fi

  [ -n "$SHOW" ] && { echo; sed 's/^/        /' "$out"; }
  rm -f "$out"
}

case "${1:-all}" in
  trytond) drill_trytond ;;
  pycsw)   drill_pycsw ;;
  all)     drill_trytond; drill_pycsw ;;
  *)       echo "usage: $0 [trytond|pycsw|all]" >&2; exit 2 ;;
esac

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
