#!/bin/sh
set -eu

workflow=${1:-.github/workflows/security.yml}

if [ ! -f "$workflow" ]; then
  printf '%s\n' "security workflow trigger contract failed: missing $workflow" >&2
  exit 1
fi

if ! awk '
  BEGIN {
    in_triggers = 0
    context = ""
    name_count = 0
    on_count = 0
    permissions_count = 0
    jobs_count = 0
    invalid_top_level = 0
    push_count = 0
    pull_request_count = 0
    push_main_count = 0
  }

  /^[^[:space:]#]/ {
    in_triggers = 0
    context = ""

    if ($0 == "name: Security") {
      name_count++
    } else if ($0 == "on:") {
      on_count++
      in_triggers = 1
    } else if ($0 == "permissions:") {
      permissions_count++
    } else if ($0 == "jobs:") {
      jobs_count++
    } else {
      invalid_top_level = 1
    }
    next
  }

  in_triggers && /^  push:[[:space:]]*$/ {
    push_count++
    context = "push"
    next
  }

  in_triggers && /^  pull_request:[[:space:]]*$/ {
    pull_request_count++
    context = "pull_request"
    next
  }

  in_triggers && /^  [^[:space:]#][^:]*:/ {
    context = "other"
    next
  }

  in_triggers && context == "push" && \
    /^    branches:[[:space:]]*\[main\][[:space:]]*$/ {
    push_main_count++
  }

  END {
    if (invalid_top_level || name_count != 1 || on_count != 1 || \
        permissions_count != 1 || jobs_count != 1 || push_count != 1 || \
        pull_request_count != 1 || push_main_count != 1) {
      exit 1
    }
  }
' "$workflow"; then
  printf '%s\n' \
    'security workflow trigger contract failed: require the exact canonical top-level grammar and one on mapping with push.branches [main] and pull_request' >&2
  exit 1
fi

if ! awk '
  BEGIN {
    scan_name_count = 0
    scan_run_count = 0
    scan_command_count = 0
    state = 0
    invalid_scan_step = 0
  }

  state == 1 {
    if ($0 == "        run: |") {
      scan_run_count++
      state = 2
      next
    }

    invalid_scan_step = 1
    state = 0
  }

  state == 2 {
    if ($0 == "          \"$RUNNER_TEMP/gitleaks\" dir . --config .gitleaks.toml --redact --no-banner") {
      scan_command_count++
      state = 3
      next
    }

    invalid_scan_step = 1
    state = 0
  }

  state == 3 {
    if ($0 == "") {
      state = 0
      next
    }

    invalid_scan_step = 1
    state = 0
  }

  $0 == "      - name: Scan exact checkout bytes" {
    scan_name_count++
    state = 1
    next
  }

  END {
    if (invalid_scan_step || state != 0 || scan_name_count != 1 || \
        scan_run_count != 1 || scan_command_count != 1) {
      exit 1
    }
  }
' "$workflow"; then
  printf '%s\n' \
    'security workflow scan contract failed: require exactly one Scan exact checkout bytes step with the canonical block-scalar gitleaks command' >&2
  exit 1
fi

printf '%s\n' 'security workflow trigger contract: PASS'
printf '%s\n' 'security workflow scan contract: PASS'
