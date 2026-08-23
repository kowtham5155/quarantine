#!/usr/bin/env bash
# Quarantine — automated phase runner
#
#   ./build.sh            run all remaining phases
#   ./build.sh 4          run only phase 4
#   ./build.sh 4 6        run phases 4 through 6
#   ./build.sh --status   show what's done
#
# State lives in .build-state (last completed phase).
# Everything is appended to BUILD_LOG.md — nothing is ever overwritten.

set -uo pipefail

PROMPTS="QUARANTINE_BUILD_PROMPTS.md"
LOG="BUILD_LOG.md"
STATE=".build-state"
MAX_REPAIRS=3
LAST_PHASE=10

# claude -p needs to write files and run npm without stopping to ask.
# This grants that. Only run this in a repo you own, on a machine you trust.
CLAUDE_FLAGS="--permission-mode acceptEdits"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_INF=$'\033[36m'; C_WARN=$'\033[33m'; C_OFF=$'\033[0m'

say()  { printf '%s\n' "${C_INF}▸ $*${C_OFF}"; }
ok()   { printf '%s\n' "${C_OK}✓ $*${C_OFF}"; }
warn() { printf '%s\n' "${C_WARN}! $*${C_OFF}"; }
die()  { printf '%s\n' "${C_ERR}✗ $*${C_OFF}"; exit 1; }

log() { printf '%s\n' "$*" >> "$LOG"; }

log_block() {                      # log_block <title> <body>
  log ""
  log "### $1"
  log ""
  log '```'
  printf '%s\n' "$2" | tail -n 200 >> "$LOG"
  log '```'
}

stamp() { date '+%Y-%m-%d %H:%M:%S'; }

# --- extract the fenced block under "## PROMPT n" ---------------------------
extract_prompt() {
  awk -v n="$1" '
    $0 ~ "^## PROMPT " n "( |$|—|-)" { found=1; next }
    found && /^```/ { if (inblock) exit; inblock=1; next }
    inblock { print }
  ' "$PROMPTS"
}

phase_title() {
  awk -v n="$1" '$0 ~ "^## PROMPT " n "( |$|—|-)" { sub(/^## /,""); print; exit }' "$PROMPTS"
}

# --- the instruction appended to every phase -------------------------------
verify_tail() {
cat <<'EOF'

---
WHEN YOU FINISH THE WORK ABOVE:
1. Run: npm run typecheck
2. Run: npm run lint
3. Run: npm run build
Fix every failure and re-run until all three pass. Do not stop while any fails.
If a command does not exist yet at this phase, skip it and say so.
Then print a short summary: files created, anything you deferred, and the final
status of each of the three commands.
EOF
}

verify() {
  local out="" rc=0 c
  for c in typecheck lint build; do
    if ! grep -q "\"$c\"" package.json 2>/dev/null; then continue; fi
    local o
    o=$(npm run "$c" 2>&1); local r=$?
    out+=$'\n===== npm run '"$c"' (exit '"$r"$') =====\n'"$o"
    [ $r -ne 0 ] && rc=1
  done
  VERIFY_OUT="$out"
  return $rc
}

run_phase() {
  local n="$1"
  local title; title=$(phase_title "$n")
  local body;  body=$(extract_prompt "$n")

  [ -z "$body" ] && die "Could not extract PROMPT $n from $PROMPTS"

  say "Phase $n — ${title:-untitled}"
  log ""
  log "---"
  log ""
  log "## Phase $n — ${title:-untitled}"
  log ""
  log "Started: $(stamp)"

  local out
  out=$(printf '%s\n%s\n' "$body" "$(verify_tail)" | claude -p $CLAUDE_FLAGS 2>&1)
  log_block "Agent output" "$out"

  # --- verify, repair, repeat ---
  local attempt=0
  while true; do
    if verify; then
      ok "Phase $n verified clean"
      log ""
      log "**Verification: PASS** — $(stamp)"
      break
    fi

    attempt=$((attempt+1))
    warn "Phase $n verification failed (repair attempt $attempt/$MAX_REPAIRS)"
    log ""
    log "**Verification: FAIL** (repair attempt $attempt) — $(stamp)"
    log_block "Errors" "$VERIFY_OUT"

    if [ $attempt -gt $MAX_REPAIRS ]; then
      log ""
      log "**PHASE $n ABANDONED** after $MAX_REPAIRS repair attempts — $(stamp)"
      log "Human intervention required. See errors above."
      die "Phase $n failed after $MAX_REPAIRS repairs. Read $LOG, fix by hand, then: ./build.sh $n"
    fi

    local fix
    fix=$(printf 'The build is failing. Fix every error below, then re-run npm run typecheck && npm run lint && npm run build until all three pass. Do not change project scope, do not delete tests to make them pass, and do not disable lint rules to silence errors — fix the actual cause.\n\n%s\n' "$VERIFY_OUT" \
          | claude -p $CLAUDE_FLAGS 2>&1)
    log_block "Repair attempt $attempt" "$fix"
  done

  # --- commit ---
  git add -A
  if git diff --cached --quiet; then
    warn "Phase $n produced no changes to commit"
    log "Commit: nothing to commit"
  else
    git commit -q -m "phase $n: ${title#PROMPT $n — }"
    ok "Committed phase $n"
    log "Commit: $(git rev-parse --short HEAD)"
  fi

  echo "$n" > "$STATE"
  log ""
  log "Finished: $(stamp)"
}

# ---------------------------------------------------------------------------
[ -f "$PROMPTS" ] || die "$PROMPTS not found. Run this from the repo root."
command -v claude >/dev/null || die "claude CLI not found on PATH."

if [ ! -f "$LOG" ]; then
  {
    echo "# Quarantine build log"
    echo ""
    echo "Append-only. Every phase, every error, every repair attempt."
    echo "Started $(stamp)"
  } > "$LOG"
fi

done_phase=0
[ -f "$STATE" ] && done_phase=$(cat "$STATE")

if [ "${1:-}" = "--status" ]; then
  echo "Last completed phase: $done_phase / $LAST_PHASE"
  echo "Log: $LOG"
  exit 0
fi

if [ $# -eq 0 ]; then
  from=$((done_phase + 1)); to=$LAST_PHASE
elif [ $# -eq 1 ]; then
  from="$1"; to="$1"
else
  from="$1"; to="$2"
fi

[ "$from" -gt "$LAST_PHASE" ] && { ok "All phases already complete."; exit 0; }

say "Running phases $from through $to"
echo

for ((p=from; p<=to; p++)); do
  run_phase "$p"
  echo
done

ok "Done. Phases $from–$to complete."
echo "Log: $LOG"
