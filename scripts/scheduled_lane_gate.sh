#!/usr/bin/env bash
# scheduled_lane_gate.sh — "main is green" gate over the repo's scheduled
# workflow lanes (#245). On main pushes, each lane's LATEST scheduled run
# must not be red. PR runs skip the gate (a PR cannot fix or cause a
# scheduled-lane failure).
#
# Codex P2 on #247 contract: an UNFINISHED lane run (null conclusion) must
# never silently count as green — poll it to a conclusion within a bounded
# budget, and if still unresolved it is surfaced as its own red verdict.
#
# Usage:
#   scheduled_lane_gate.sh              # run the gate (CI step)
#   scheduled_lane_gate.sh --selftest   # assert the verdict contract
# Env (gate mode): GITHUB_REPOSITORY, GH_TOKEN,
#                  LANE_POLL_BUDGET_S (default 600), LANE_POLL_INTERVAL_S (default 30)
set -euo pipefail

LANES="${LANES:-gitleaks.yml shc-reaper.yml fips-core-canary.yml protocol-drift.yml}"
LANE_POLL_BUDGET_S="${LANE_POLL_BUDGET_S:-600}"
LANE_POLL_INTERVAL_S="${LANE_POLL_INTERVAL_S:-30}"

# Verdict contract: only these count as pass. Deliberately does NOT include
# in-progress or unresolved — see --selftest.
verdict_is_pass() {
    case "$1" in
        success|never-run) return 0 ;;
        *) return 1 ;;
    esac
}

# Map a workflow-runs API page's latest entry to a verdict string.
# jq fixture contract (selftested):
#   no runs                    -> never-run
#   conclusion null (running)  -> in-progress   (+ echo run id for polling)
#   conclusion present         -> that conclusion
map_latest_run() {
    gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/${1}/runs?event=schedule&branch=main&per_page=1" \
        --jq 'if (.workflow_runs | length) == 0 then ["never-run", "", ""] else [.workflow_runs[0].conclusion // "in-progress", .workflow_runs[0].html_url, (.workflow_runs[0].id | tostring)] end | @tsv'
}

# Poll one run to a conclusion within the budget. Echoes the final verdict.
poll_run_to_conclusion() {
    local run_id="$1" url="$2" deadline now verdict
    now=$(date +%s)
    deadline=$((now + LANE_POLL_BUDGET_S))
    while [ "$now" -lt "$deadline" ]; do
        verdict=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}" \
            --jq '.conclusion // "in-progress"')
        if [ "$verdict" != "in-progress" ]; then
            echo "$verdict"
            return 0
        fi
        sleep "$LANE_POLL_INTERVAL_S"
        now=$(date +%s)
    done
    echo "unresolved"
}

selftest() {
    local failures=0
    t() { # t <expected: pass|red> <verdict>
        local expect="$1" verdict="$2" got
        if verdict_is_pass "$verdict"; then got=pass; else got=red; fi
        if [ "$got" != "$expect" ]; then
            echo "FAIL: verdict '$verdict' -> $got, expected $expect" >&2
            failures=$((failures + 1))
        fi
    }
    t pass success
    t red failure
    t red cancelled
    t red timed_out
    t red startup_failure
    t red skipped
    t red action_required
    t red in-progress   # Codex P2: unfinished must NOT be green
    t red unresolved    # still-running after budget must NOT be green
    t pass never-run    # a lane never yet scheduled does not block main
    t red unreachable   # API failure fails closed
    if [ "$failures" -ne 0 ]; then
        echo "selftest: $failures verdict-contract failures" >&2
        exit 1
    fi
    echo "selftest: verdict contract OK (in-progress and unresolved are NOT green)"
}

run_gate() {
    local red=0 lane verdict url run_id
    {
        echo ""
        echo "## Scheduled lane health (main)"
        echo ""
        echo "| Lane | Latest scheduled run | Verdict |"
        echo "|------|----------------------|---------|"
    } >> "$GITHUB_STEP_SUMMARY"
    for lane in $LANES; do
        verdict=""; url=""; run_id=""
        IFS=$'\t' read -r verdict url run_id < <(map_latest_run "$lane") || verdict="unreachable"
        verdict="${verdict:-unreachable}"
        # Codex P2 on #247: an unfinished run is polled to a conclusion
        # within the budget; still-running becomes 'unresolved' (red) —
        # never silently green.
        if [ "$verdict" = "in-progress" ] && [ -n "$run_id" ]; then
            verdict=$(poll_run_to_conclusion "$run_id" "$url")
        fi
        echo "| ${lane} | ${url:-n/a} | ${verdict} |" >> "$GITHUB_STEP_SUMMARY"
        if ! verdict_is_pass "$verdict"; then
            echo "::error::scheduled lane ${lane}: latest scheduled run is ${verdict} (${url:-no url})"
            red=1
        fi
    done
    if [ "$red" -ne 0 ]; then
        echo "::error::one or more scheduled lanes are red on main — see the Scheduled lane health table above"
        exit 1
    fi
    echo "all scheduled lanes green on main"
}

case "${1:-}" in
    --selftest) selftest ;;
    *) run_gate ;;
esac
