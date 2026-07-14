#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker daemon is unavailable' >&2
  exit 1
fi

project="bowline-smoke-$$"
compose="docker compose -p $project -f docker-compose.production.yml"
report=$(mktemp)

cleanup() {
  rm -f "$report"
  $compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

BOWLINE_VCS_REF=$(git rev-parse --verify HEAD 2>/dev/null || printf unknown)
export BOWLINE_VCS_REF
$compose build --pull
$compose up -d echo
$compose run --rm --no-deps bowline preflight \
  --config /config/bowline.example.yaml --json >/dev/null
$compose up -d bowline

deadline=$(( $(date +%s) + 60 ))
until curl -fsS http://127.0.0.1:8080/health/ready >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    $compose logs >&2
    printf '%s\n' 'Bowline did not become ready' >&2
    exit 1
  fi
  sleep 1
done

curl -fsS http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-5-mini","messages":[{"role":"user","content":"normal"}]}' >/dev/null
curl -fsS http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-bowline-app: smoke-test' \
  -H 'x-bowline-task-class: mechanical' \
  -d '{"model":"gpt-5-mini","messages":[{"role":"user","content":"identified"}]}' >/dev/null
curl -fsSN http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-5-mini","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"stream"}]}' \
  | grep -Fq 'data: [DONE]'

container=$($compose ps -q bowline)
test -n "$container"
docker kill --signal TERM "$container" >/dev/null
exit_code=$(docker wait "$container")
test "$exit_code" -eq 0

$compose run --rm --no-deps bowline report \
  --config /config/bowline.example.yaml >"$report"
grep -Fq -- '- Complete: true' "$report"
grep -Fq -- '- Accepted: 3' "$report"
grep -Fq -- '- Recorded: 3' "$report"
grep -Fq -- '- Dropped: 0' "$report"
grep -Fq -- '- Truncated: 0' "$report"

printf '%s\n' 'docker smoke: PASS (3 accepted, 3 recorded, 0 dropped)'
