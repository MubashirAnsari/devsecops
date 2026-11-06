#!/usr/bin/env bash
# add_github_webhooks.sh - add the SIEM webhook to every repository an owner has.
# Idempotent: repos that already have a hook pointing at the receiver URL are
# reported (exists / exists-drift) and never changed or duplicated.
#
# DRY RUN BY DEFAULT. Nothing is created without --apply.
# Re-running the dry run after --apply doubles as verification: it shows each
# hook's last delivery code (expect 202 from the ping).
#
# Needs: gh (GitHub CLI) and the AWS CLI.
#   GH_TOKEN  a token for the repo owner with webhook admin rights
#             (classic: admin:repo_hook, fine-grained: "Webhooks: Read and write" on all repos)
#             Set it for this shell only:  read -rs GH_TOKEN; export GH_TOKEN
#
# Usage:
#   ./add_github_webhooks.sh --owner ACCOUNT                       # dry run, all repos
#   ./add_github_webhooks.sh --owner ACCOUNT --org                 # owner is an organization
#   ./add_github_webhooks.sh --owner ACCOUNT --repo NAME           # one repo
#   ./add_github_webhooks.sh --owner ACCOUNT --apply --limit 3     # canary: first 3 repos needing a hook
#   ./add_github_webhooks.sh --owner ACCOUNT --apply               # all repos
#   add --ref-repo NAME to require that NAME already has the same hook (a verified test repo)
#
# The secret is read from Secrets Manager only with --apply, kept in a shell
# variable and sent to gh on stdin. It is never printed, logged or passed as
# a command-line argument.

set -uo pipefail
set +x
export LC_ALL=C

OWNER=""
IS_ORG=0
REGION="${AWS_REGION:-us-east-1}"
FUNCTION="${FUNCTION:-github-webhook-receiver}"
SECRET_ID="${SECRET_ID:-github-webhook-secret}"
REF_REPO=""                     # optional: a repo where the hook was set up and tested by hand
EVENTS=(branch_protection_rule create delete deploy_key member pull_request push repository repository_ruleset)
PAUSE_WRITE=1.2                 # GitHub secondary rate limit
PAUSE_READ=0.3

APPLY=0; LIMIT=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --owner) OWNER="${2:?--owner needs a name}"; shift ;;
    --org) IS_ORG=1 ;;
    --ref-repo) REF_REPO="${2:?--ref-repo needs a name}"; shift ;;
    --apply) APPLY=1 ;;
    --limit) LIMIT="${2:?--limit needs a number}"; shift ;;
    --repo)  ONLY="${2:?--repo needs a name}"; shift ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

die()  { echo "ERROR: $*" >&2; exit 1; }
[ -n "$OWNER" ] || die "--owner is required (see --help)"
nocr() { tr -d '\r'; }
ERRF=$(mktemp); trap 'rm -f "$ERRF"; unset SECRET BODY' EXIT

# ---------- preflight ----------
[ -n "${GH_TOKEN:-}" ] || die "GH_TOKEN is not set in this shell"
case "$GH_TOKEN" in *$'\e'*|*$'\r'*|*$'\n'*|*' '*) die "GH_TOKEN contains paste markers or whitespace - strip them first" ;; esac

login=$(gh api user --jq .login 2>"$ERRF" | nocr) || die "gh api user failed: $(cat "$ERRF")"
if [ "$IS_ORG" = 0 ]; then
  [ "$login" = "$OWNER" ] || die "gh is acting as '$login', expected '$OWNER'"
fi

URL=$(aws lambda get-function-url-config --region "$REGION" --function-name "$FUNCTION" \
      --query FunctionUrl --output text 2>"$ERRF" | nocr) || die "could not read Function URL: $(cat "$ERRF")"
case "$URL" in https://*.lambda-url."$REGION".on.aws*) ;; *) die "unexpected Function URL: $URL" ;; esac
URLN=${URL%/}

WANT=$(printf '%s\n' "${EVENTS[@]}" | sort | paste -sd, -)
EV_JSON=$(printf '"%s",' "${EVENTS[@]}"); EV_JSON=${EV_JSON%,}

# jq filter: our hook(s) only -> id, active, events, content_type, insecure_ssl, last code
HOOK_JQ=".[] | select((.config.url // \"\" | rtrimstr(\"/\")) == \"$URLN\")
         | [(.id|tostring), (.active|tostring), (.events|sort|join(\",\")),
            (.config.content_type // \"\"), (.config.insecure_ssl // \"\"),
            ((.last_response.code // \"none\")|tostring)] | @tsv"

# Optional: a hand-tested repo must already carry the identical hook (same URL and events)
if [ -n "$REF_REPO" ]; then
  ref=$(gh api "repos/$OWNER/$REF_REPO/hooks" --jq "$HOOK_JQ" 2>"$ERRF" | nocr) || die "cannot list hooks on $REF_REPO: $(cat "$ERRF")"
  [ -n "$ref" ] || die "$REF_REPO has no hook with $URLN - URL mismatch?"
  ref_events=$(printf '%s\n' "$ref" | head -1 | cut -f3)
  [ "$ref_events" = "$WANT" ] || die "event list differs from $REF_REPO: ref=[$ref_events] script=[$WANT]"
fi

if [ "$APPLY" = 1 ]; then
  SECRET=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_ID" \
           --query SecretString --output text 2>"$ERRF" | tr -d '\r\n') || die "cannot read secret: $(cat "$ERRF")"
  [[ "$SECRET" =~ ^[0-9a-f]{64}$ ]] || die "secret is not 64 hex chars (length ${#SECRET})"
fi

# ---------- repo list (fresh every run) ----------
REPOS=()
if [ -n "$ONLY" ]; then
  REPOS=("$ONLY")
else
  if [ "$IS_ORG" = 1 ]; then LIST="orgs/$OWNER/repos?type=all&per_page=100"; else LIST="user/repos?affiliation=owner&per_page=100"; fi
  while IFS= read -r r; do [ -n "$r" ] && REPOS+=("$r"); done < <(
    gh api "$LIST" --paginate \
      --jq '.[] | select(.owner.login == "'"$OWNER"'") | select(.archived | not) | .name' 2>"$ERRF" | nocr | sort)
  [ ${#REPOS[@]} -gt 0 ] || die "no repos listed: $(cat "$ERRF")"
fi

LOG="webhook_rollout_$(date -u +%Y%m%dT%H%M%SZ).tsv"
printf 'repo\tstatus\thook_id\tlast_code\tdetail\n' > "$LOG"
echo "gh as: $login | URL: $URLN | events: $WANT"
echo "mode: $([ "$APPLY" = 1 ] && echo APPLY || echo DRY-RUN) | repos: ${#REPOS[@]} | limit: $LIMIT | log: $LOG"
echo

added=0; would=0; exists=0; drift=0; failed=0; created_or_planned=0
for r in "${REPOS[@]}"; do
  out=$(gh api "repos/$OWNER/$r/hooks" --paginate --jq "$HOOK_JQ" 2>"$ERRF" | nocr); rc=$?
  if [ $rc -ne 0 ]; then
    msg=$(tr '\n\t' '  ' < "$ERRF" | cut -c1-200)
    printf '%-45s %s\n' "$r" "failed (list hooks): $msg"
    printf '%s\tfailed\t\t\tlist hooks: %s\n' "$r" "$msg" >> "$LOG"; failed=$((failed+1)); sleep "$PAUSE_READ"; continue
  fi

  if [ -n "$out" ]; then
    n=$(printf '%s\n' "$out" | wc -l | tr -d ' ')
    IFS=$'\t' read -r id active ev ct ssl code <<< "$(printf '%s\n' "$out" | head -1)"
    problems=""
    [ "$active" = "true" ] || problems+="inactive "
    [ "$ev" = "$WANT" ]    || problems+="events=[$ev] "
    [ "$ct" = "json" ]     || problems+="content_type=$ct "
    [ "$ssl" = "0" ]       || problems+="ssl_verify_off "
    [ "$n" -gt 1 ]         && problems+="duplicates=$n "
    if [ -z "$problems" ]; then
      printf '%-45s exists (id %s, last %s)\n' "$r" "$id" "$code"
      printf '%s\texists\t%s\t%s\t\n' "$r" "$id" "$code" >> "$LOG"; exists=$((exists+1))
    else
      printf '%-45s EXISTS-DRIFT (id %s): %s\n' "$r" "$id" "$problems"
      printf '%s\texists-drift\t%s\t%s\t%s\n' "$r" "$id" "$code" "$problems" >> "$LOG"; drift=$((drift+1))
    fi
    sleep "$PAUSE_READ"; continue
  fi

  # no hook yet
  if [ "$LIMIT" -gt 0 ] && [ "$created_or_planned" -ge "$LIMIT" ]; then
    printf '%-45s skipped (limit reached)\n' "$r"
    printf '%s\tskipped-limit\t\t\t\n' "$r" >> "$LOG"; continue
  fi
  created_or_planned=$((created_or_planned+1))

  if [ "$APPLY" != 1 ]; then
    printf '%-45s would add\n' "$r"
    printf '%s\twould-add\t\t\t\n' "$r" >> "$LOG"; would=$((would+1)); sleep "$PAUSE_READ"; continue
  fi

  BODY=$(printf '{"name":"web","active":true,"events":[%s],"config":{"url":"%s","content_type":"json","insecure_ssl":"0","secret":"%s"}}' \
         "$EV_JSON" "$URL" "$SECRET")
  id=$(printf '%s' "$BODY" | gh api -X POST "repos/$OWNER/$r/hooks" --input - --jq '.id' 2>"$ERRF" | nocr); rc=$?
  unset BODY
  if [ $rc -eq 0 ] && [ -n "$id" ]; then
    printf '%-45s added (id %s)\n' "$r" "$id"
    printf '%s\tadded\t%s\t\t\n' "$r" "$id" >> "$LOG"; added=$((added+1))
  else
    msg=$(tr '\n\t' '  ' < "$ERRF" | cut -c1-200)
    printf '%-45s FAILED: %s\n' "$r" "$msg"
    printf '%s\tfailed\t\t\tcreate: %s\n' "$r" "$msg" >> "$LOG"; failed=$((failed+1))
  fi
  sleep "$PAUSE_WRITE"
done

echo
echo "summary: added=$added would_add=$would exists=$exists exists_drift=$drift failed=$failed total=${#REPOS[@]}"
echo "log: $LOG (no secret in it)"
[ "$failed" -eq 0 ] && [ "$drift" -eq 0 ]
