#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

required_docs='README.md
docs/quickstart.md
docs/methodology.md
docs/architecture.md
docs/production-pov.md
docs/configuration.md
docs/policy.md
docs/registry.md
docs/reporting.md
docs/operations.md
docs/security.md
docs/threat-model.md
docs/limitations.md'
required_docs="$required_docs
docs/customer-quality.md
docs/actionable-economics.md"
required_docs="$required_docs
docs/controlled-enforcement.md"

failures=0
for file in $required_docs; do
  if [ ! -f "$file" ]; then
    printf '%s\n' "missing public document: $file" >&2
    failures=$((failures + 1))
  fi
done
[ "$failures" -eq 0 ] || exit 1

public_markdown_files=$(find . \( -path './.git' -o -path './target' \) -prune -o \
  -type f -name '*.md' -print | LC_ALL=C sort)
for file in ./CHANGELOG.md ./examples/enforcement/README.md; do
  if ! printf '%s\n' "$public_markdown_files" | grep -Fxq "$file"; then
    printf '%s\n' "public Markdown corpus is missing: $file" >&2
    failures=$((failures + 1))
  fi
done
public_markdown_text=$(
  while IFS= read -r file; do
    cat "$file"
    printf '\n.\n'
  done <<EOF
$public_markdown_files
EOF
)

for field in listen upstream actual_supply_id policy_bundle registry_feed local_endpoints ledger_dir \
  tco floors trusted_proxy_cidrs runtime connect_timeout_ms response_header_timeout_ms \
  stream_idle_timeout_ms shutdown_grace_ms writer_queue_capacity accounting_limit_bytes \
  ledger_segment_bytes ledger_max_segments enforcement global_candidate_in_flight kill_switch \
  actuators routes rollout_ppm model_authority fallback promotion; do
  if ! grep -Fq "\`$field\`" docs/configuration.md; then
    printf '%s\n' "configuration field is undocumented: $field" >&2
    failures=$((failures + 1))
  fi
done

for command in 'bowline health' 'bowline preflight' 'bowline serve' 'bowline report' \
  'bowline import observations' 'bowline policy validate' 'bowline registry show' \
  'bowline registry probe' 'bowline canary validate' 'bowline canary run' \
  'bowline canary report'; do
  if ! grep -R -Fq "$command" README.md docs; then
    printf '%s\n' "CLI command is undocumented: $command" >&2
    failures=$((failures + 1))
  fi
done

for command in 'bowline billing validate' 'bowline billing import' \
  'bowline economics validate' 'bowline economics report'; do
  if ! grep -R -Fq "$command" README.md docs; then
    printf '%s\n' "actionable-economics command is undocumented: $command" >&2
    failures=$((failures + 1))
  fi
done

for command in 'bowline kill arm' 'bowline kill bypass'; do
  if ! grep -R -Fq "$command" README.md docs; then
    printf '%s\n' "controlled-enforcement command is undocumented: $command" >&2
    failures=$((failures + 1))
  fi
done

if ! grep -R -Fq 'bowline promotion seal' README.md docs; then
  printf '%s\n' 'controlled-enforcement command is undocumented: bowline promotion seal' >&2
  failures=$((failures + 1))
fi

controlled_text=$public_markdown_text
controlled_text_flat=$(printf '%s' "$controlled_text" | tr '\n' ' ')
for claim in \
  'Observe is the default when `enforcement` is absent.' \
  'Allocation authority requires an exact allowlisted workload, rollout bucket, and fresh verified promotion grant.' \
  'Allocation authority is limited to OpenAI-compatible Chat Completions and Responses.' \
  'A request is dispatched to zero or one upstream target.' \
  'Bowline never follows redirects, retries a completion, or falls back after a candidate attempt.' \
  'Pre-dispatch fallback is exactly `bypass` or `fail-closed`.' \
  'Pre-dispatch `fail-closed` returns HTTP 503 with stable code `enforcement-fail-closed`.' \
  'Replacement evidence failure returns HTTP 503 with stable code `evidence-unavailable`.' \
  'A candidate timeout before response headers returns local HTTP 504; another candidate dispatch failure before response headers returns local HTTP 502.' \
  'A received candidate HTTP response, including 401, 403, or 5xx, is returned as the first target response and is not rewritten as a local failure.' \
  'A candidate stream failure after response headers terminates that stream without retry or fallback to the original upstream.' \
  'Startup never arms authority automatically or rewrites an existing valid kill state.' \
  'An existing strict private `armed` state remains armed; missing, invalid, or `bypass` kill state removes authority and each route applies its configured pre-dispatch fallback, which can be `bypass` or `fail-closed`.' \
  'Run `bowline promotion seal --config <config> --route <route-id>` only after evidence generation and while the kill state is `bypass`.' \
  'The authorization sidecar is a local descriptor-protected provenance seal, not a signature or organizational approval.' \
  'Authority requires exact equality with the active policy bundle, registry-source bytes, and normalized owned-cost catalog.' \
  'Candidate selection requires exact runtime task, application identity, and canonical tag binding to the route and verified grant.' \
  'An unresolved or invalid application identity has zero allocation authority and uses the configured pre-dispatch fallback.' \
  'Embeddings remain observe/recommend-only with zero allocation authority.' \
  'Final pre-dispatch authority loss first records `pre-dispatch-rejected`, then durably records the exact configured `bypass` or `fail-closed` replacement before any fallback.' \
  'Modeled enforced delta is available only for a successful candidate HTTP 2xx response with observed complete token counts and both approved rates.' \
  'One deployment is one enterprise security domain.' \
  'Enforced modeled delta is approved counterfactual cost minus observed actual cost over identical complete token counts; unavailable evidence remains unavailable.'; do
  if ! printf '%s' "$controlled_text_flat" | grep -Fq "$claim"; then
    printf '%s\n' "required controlled-enforcement claim is missing: $claim" >&2
    failures=$((failures + 1))
  fi
done

false_startup_claim_pattern='starts?[[:space:]]+(in|at)[[:space:]]+`?bypass|killed([ -]by[ -])default'
for fixture in \
  'Controlled enforcement starts in bypass.' \
  'Authority starts at `bypass`.' \
  'Controlled enforcement is killed by default.' \
  'Controlled enforcement is killed-by-default.'; do
  if ! printf '%s\n' "$fixture" | grep -Eiq "$false_startup_claim_pattern"; then
    printf '%s\n' "startup claim guard does not reject fixture: $fixture" >&2
    failures=$((failures + 1))
  fi
done
if printf '%s\n' "$public_markdown_text" | grep -n -Ei "$false_startup_claim_pattern"; then
  printf '%s\n' 'false controlled-enforcement startup claim found' >&2
  failures=$((failures + 1))
fi

unsafe_authority_claim_pattern='configuration([[:space:]]+alone)?[[:space:]]+(proves|establishes|authorizes|activates|is[[:space:]]+sufficient[[:space:]]+for)[[:space:]]+(promotion|authority)|startup[[:space:]]+(automatically[[:space:]]+)?(seals|arms|authorizes|activates)[[:space:]]+(promotion|authority)|((non[- ]?2xx|[45]xx|failed[[:space:]]+responses?)[^.!?]{0,100}(produces?|yields?|creates?|counts?[[:space:]]+toward)[^.!?]{0,60}(savings|modeled[[:space:]]+delta)|(savings|modeled[[:space:]]+delta)[^.!?]{0,60}(includes?|uses?|counts?)[^.!?]{0,100}(non[- ]?2xx|[45]xx|failed[[:space:]]+responses?))'
for fixture in \
  'Configuration alone proves promotion.' \
  'Startup automatically seals authority.' \
  'Startup arms promotion.' \
  'Non-2xx usage produces modeled delta.' \
  'Savings include failed responses with usage.'; do
  if ! printf '%s\n' "$fixture" | grep -Eiq "$unsafe_authority_claim_pattern"; then
    printf '%s\n' "authority claim guard does not reject fixture: $fixture" >&2
    failures=$((failures + 1))
  fi
done
for fixture in \
  'Configuration does not establish authority without the sealed sidecar.' \
  'Startup never arms authority automatically.' \
  'Only successful HTTP 2xx responses can produce modeled delta.'; do
  if printf '%s\n' "$fixture" | grep -Eiq "$unsafe_authority_claim_pattern"; then
    printf '%s\n' "authority claim guard rejects factual fixture: $fixture" >&2
    failures=$((failures + 1))
  fi
done
if printf '%s\n' "$public_markdown_text" | grep -n -Ei "$unsafe_authority_claim_pattern"; then
  printf '%s\n' 'unsafe authority or modeled-delta claim found in public documentation' >&2
  failures=$((failures + 1))
fi

has_unsupported_controlled_claim() {
  perl -0777 -e '
    use strict;
    use warnings;
    my $text = lc <>;
    $text =~ s/\r\n?/\n/g;
    $text =~ s/^[ \t]*(?:#{1,6}[ \t]+|>[ \t]*|[-*+][ \t]+|[0-9]+[.)][ \t]+)//mg;
    $text =~ s/[[:space:]]+/ /g;
    my @approved_nonclaims = (
      q{bowline does not automatically route requests},
      q{bowline does not use a learned model to place requests},
      q{bowline does not provide universal quality},
      q{bowline does not provide universal quality or guaranteed savings},
      q{bowline does not guarantee quality for every workload},
      q{bowline does not guarantee savings},
      q{bowline does not report realized savings},
      q{bowline does not report achieved or realized savings},
      q{bowline does not retry or fall back after a candidate attempt},
      q{bowline does not fail over after a candidate attempt},
      q{bowline does not send a failed candidate call again to the original upstream},
      q{bowline does not execute each provider request exactly once},
      q{bowline does not provide exactly-once execution of provider requests},
      q{bowline does not execute provider requests once and only once},
      q{bowline does not coordinate circuit breakers across replicas},
      q{circuit breakers are process-local and are not distributed across replicas},
      q{breaker state is process-local and does not survive restart or replicate},
      q{bowline does not provide an administration api},
      q{bowline has no management plane},
      q{bowline has no route administration service},
      q{bowline does not isolate multiple tenants},
      q{bowline does not provide provider-native support or content dlp},
      q{bowline does not provide provider-native support},
      q{bowline does not support provider-native adapters},
      q{bowline has no built-in provider-specific integration},
      q{bowline is not dlp},
      q{bowline does not perform content dlp},
      q{bowline does not scan prompts or block sensitive content},
      q{bowline does not provide secure multi-tenancy},
      q{bowline has no dashboard and does not provide secure multi-tenancy},
      q{bowline does not isolate different customers inside one process},
      q{bowline does not use learned routing},
      q{bowline never follows redirects, retries a completion, or falls back after a candidate attempt},
      q{never retries or sends the original request after a candidate attempt},
      q{a candidate stream failure after response headers terminates that stream without retry or fallback to the original upstream},
      q{do not expect a candidate request to retry or switch upstream after dispatch},
      q{no redirects/retries/post-attempt fallback},
      q{there is no redirect following, completion retry, or original-upstream fallback after a candidate attempt},
      q{a candidate attempt never retries or reaches the original upstream afterward},
      q{each candidate/case request and judge evaluation is dispatched at most once; bowline does not retry},
      q{opportunities are counterfactual modeled evidence, not realized savings},
      q{they are not realized savings},
      q{counterfactuals are labeled with their confidence and are not presented as realized savings},
      q{controlled enforcement does not inspect prompt or response content, authenticate operator-supplied billing inputs, establish dataset representativeness, approve spend, or establish realized savings},
      q{the value is a counterfactual arithmetic extrapolation, not demand modeling, a budget, a guarantee, a forecast, an accounting result, or evidence of savings already achieved},
      q{economics reports are static private bundles, not an analytics service, forecast, migration control, or proof of achieved savings},
      q{it is evidence for a bounded dataset and evaluator configuration, not a universally applicable quality conclusion},
      q{it is not dlp},
      q{no dlp claim},
      q{has no content-classification or egress-tripwire capability},
      q{workload identity policy only: no prompt/response content classification or blocking},
      q{controlled enforcement does not inspect prompt or response content},
      q{it is file import, not a listener, collector, log tailer, or provider-native schema detector},
      q{neither example claims a universal or provider-native log schema},
      q{there is no pre-dispatch charge guarantee, invoice download, provider-specific billing adapter, or spend approval},
      q{provider-specific adapters and secure multi-domain operation are outside v1},
      q{application, team, environment, cost center, route, and task-class dimensions do not create tenant isolation},
      q{not tenant boundaries, authorization scopes, or secure isolation},
      q{bowline does not provide tenant isolation inside one process}
    );
    my @capabilities = (
      qr{\b(?:automatic(?:ally)?|autonomous(?:ly)?|learned|adaptive|trained|model[- ]driven)\b[^.;!?]{0,100}\b(?:rout\w*|select\w*|plac\w*|direct\w*)\b}i,
      qr{\b(?:rout\w*|select\w*|plac\w*|direct\w*)\b[^.;!?]{0,100}\b(?:automatic(?:ally)?|autonomous(?:ly)?|learned|adaptive|trained|model[- ]driven)\b}i,
      qr{\b(?:universal(?:ly)?|guarantee\w*|(?:every|all)\s+workloads?)\b[^.;!?]{0,80}\bqualit\w*\b}i,
      qr{\bqualit\w*\b[^.;!?]{0,80}\b(?:universal(?:ly)?|guarantee\w*|(?:every|all)\s+workloads?)\b}i,
      qr{\b(?:guarantee\w*|realized|achieved|delivered|proven|actual)\b[^.;!?]{0,60}\bsavings?\b}i,
      qr{\bsavings?\b[^.;!?]{0,60}\b(?:guarantee\w*|realized|achieved|delivered|proven|actual)\b}i,
      qr{\b(?:after|following|post[- ]attempt)\b[^.;!?]{0,120}\b(?:candidate|actuator)\b[^.;!?]{0,120}\b(?:retr(?:y|ies)|sent\s+again|falls?\s+back|fallback|fail(?:s|ed)?\s+over|switch\w*\s+upstream|original\s+upstream)\b}i,
      qr{\b(?:retr(?:y|ies)|sent\s+again|falls?\s+back|fallback|fail(?:s|ed)?\s+over|switch\w*\s+upstream|original\s+upstream)\b[^.;!?]{0,120}\bafter\b[^.;!?]{0,80}\b(?:candidate|actuator)\b}i,
      qr{\b(?:candidate|actuator)\b[^.;!?]{0,120}\b(?:retr(?:y|ies)|sent\s+again|falls?\s+back|fail(?:s|ed)?\s+over|switch\w*\s+upstream|original\s+upstream)\b}i,
      qr{\bretr(?:y|ies)\b[^.;!?]{0,40}\bcompletion\b}i,
      qr{\b(?:provider|upstream|request|dispatch|execut\w*)\b[^.;!?]{0,100}\b(?:exactly[- ]once|once\s+and\s+only\s+once)\b}i,
      qr{\b(?:exactly[- ]once|once\s+and\s+only\s+once)\b[^.;!?]{0,100}\b(?:provider|upstream|request|dispatch|execut\w*)\b}i,
      qr{\b(?:provider|upstream)\b[^.;!?]{0,60}\b(?:call|request)\b[^.;!?]{0,60}\b(?:one\s+time|never\s+more)\b}i,
      qr{\b(?:one\s+time|never\s+more)\b[^.;!?]{0,60}\b(?:provider|upstream)\b[^.;!?]{0,60}\b(?:call|request)\b}i,
      qr{\b(?:circuit|breaker)\w*\b[^.;!?]{0,100}\b(?:distributed|durable|replica\w*|shared|surviv\w*\s+restart)\b}i,
      qr{\b(?:distributed|durable|replica\w*|shared|surviv\w*\s+restart)\b[^.;!?]{0,100}\b(?:circuit|breaker)\w*\b}i,
      qr{\b(?:management\s+plane|administration\s+(?:api|console|service)|route\s+administration\s+service|control\s+service|administer\w*\s+routes?|central\s+(?:console|dashboard)\s+(?:configur\w*|manag\w*|administer\w*|control\w*)\s+routes?)\b}i,
      qr{\b(?:provider[- ]native|native\s+provider|provider[- ]specific)\b[^.;!?]{0,100}\b(?:support|adapter\w*|integration\w*|detector|native\s+semantics)\b}i,
      qr{\b(?:support|adapter\w*|integration\w*|detector|native\s+semantics)\b[^.;!?]{0,100}\b(?:provider[- ]native|native\s+provider|provider[- ]specific)\b}i,
      qr{\bdlp\b}i,
      qr{\b(?:prompts?|response\s+content|payloads?|sensitive\s+data)\b[^.;!?]{0,100}\b(?:inspect\w*|scan\w*|classif\w*|block\w*)\b}i,
      qr{\b(?:inspect\w*|scan\w*|classif\w*|block\w*)\b[^.;!?]{0,100}\b(?:prompts?|response\s+content|payloads?|sensitive\s+data)\b}i,
      qr{\b(?:multi[- ]tenan\w*|multi[- ]user\s+isolation|tenant\s+isolation|isolat\w*\s+(?:multiple|different|separate)?\s*tenants?|different\s+customers\s+share\s+one\s+process|customer\s+workloads?\s+are\s+isolat\w*\s+from\s+each\s+other\s+inside\s+one\s+process)\b}i
    );

    # This is an accidental-claim regression guard, not semantic proof against
    # adversarial authors. Only a complete normalized sentence/clause may use an
    # approved nonclaim; substrings inside negation or contradictory prose remain scanned.
    my %approved = map { $_ => 1 } @approved_nonclaims;
    my @clauses = split /(?:[.!?;]+\s+|,\s*(?:but|yet|however)\s+)/, $text;
    for my $clause (@clauses) {
      $clause =~ s/^\s+|\s+$//g;
      $clause =~ s/[.!?;]+$//;
      next if $clause eq q{} || $approved{$clause};
      for my $capability (@capabilities) {
        if ($clause =~ $capability) {
          warn "unsupported controlled claim clause: $clause\nmatch: $&\n"
            if $ENV{CLAIM_GUARD_DEBUG};
          exit 0;
        }
      }
    }
    exit 1;
  '
}
for fixture in \
  'Bowline automatically routes requests' \
  'executes each provider request exactly once' \
  'coordinates circuit breakers across replicas' \
  'ships an administration API' \
  'isolates multiple tenants' \
  'Bowline provides automatic routing' 'Bowline uses learned routing' \
  'Bowline guarantees universal quality' 'Bowline guarantees realized savings' \
  'Bowline reports realized savings' \
  'Bowline ensures universal quality' 'Bowline delivers guaranteed savings' \
  'Bowline falls back after a candidate attempt' 'Bowline retries a completion' \
  'Candidate failures trigger a retry against the original upstream' \
  'Bowline guarantees exactly-once provider execution' \
  'Bowline provides durable distributed circuits' 'Bowline includes a management plane' \
  'Bowline provides provider-native support' \
  'Native provider adapters are included' 'The gateway performs content DLP' \
  'Bowline provides DLP' 'Bowline provides secure multi-tenancy' \
  'Bowline fails over to the original upstream after a candidate attempt.' \
  'Savings are guaranteed.' 'Quality is universal.' \
  'Bowline has a management plane.' \
  'Bowline supports provider-native adapters.' \
  'Bowline supports content DLP.' \
  'Circuit breakers are distributed across replicas.' \
  'Bowline provides exactly-once execution of provider requests.' \
  'Bowline has no dashboard and provides secure multi-tenancy.' \
  'A learned model places each request.' \
  'Every workload receives guaranteed quality.' \
  'Savings in this report have already been achieved.' \
  'Following an actuator dispatch, a failed call is sent again to the original upstream.' \
  'Each request to a provider is executed once and only once.' \
  'Breaker state is shared and survives restart on every replica.' \
  'Operators administer routes through a control service.' \
  'Built-in provider-specific integrations preserve native semantics.' \
  'Prompts are scanned to block sensitive data.' \
  'Different customers share one process with isolated data.' \
  'Bowline does not retry old jobs. Candidate failures are sent to the original upstream.' \
  'It is false that Bowline does not automatically route requests.' \
  'Bowline maintains quality for all workloads.' \
  'The central console configures routes.' \
  'Customer workloads are isolated from each other inside one process.' \
  'Each provider call happens one time and never more.' \
  'Bowline has no dashboard, but provides secure multi-tenancy.' \
  'Bowline does not automatically route requests, but it automatically places every request.'; do
  if ! printf '%s\n' "$fixture" | has_unsupported_controlled_claim; then
    printf '%s\n' "controlled claim guard does not reject fixture: $fixture" >&2
    failures=$((failures + 1))
  fi
done
for fixture in \
  'Bowline does not automatically route requests.' \
  'Bowline does not execute each provider request exactly once.' \
  'Bowline does not coordinate circuit breakers across replicas.' \
  'Bowline does not provide an administration API.' \
  'Bowline does not isolate multiple tenants.' \
  'Bowline does not provide universal quality or guaranteed savings.' \
  'Bowline does not report realized savings.' \
  'Bowline does not retry or fall back after a candidate attempt.' \
  'Bowline does not provide provider-native support or content DLP.' \
  'Bowline does not use learned routing.' \
  'Bowline never follows redirects, retries a completion, or falls back after a candidate attempt.' \
  'Bowline does not fail over after a candidate attempt.' \
  'Bowline does not guarantee savings.' \
  'Bowline does not provide universal quality.' \
  'Bowline has no management plane.' \
  'Bowline does not support provider-native adapters.' \
  'Bowline does not perform content DLP.' \
  'Bowline does not provide provider-native support.' \
  'Circuit breakers are process-local and are not distributed across replicas.' \
  'Bowline does not provide exactly-once execution of provider requests.' \
  'Bowline has no dashboard and does not provide secure multi-tenancy.' \
  'Bowline does not use a learned model to place requests.' \
  'Bowline does not guarantee quality for every workload.' \
  'Bowline does not report achieved or realized savings.' \
  'Bowline does not send a failed candidate call again to the original upstream.' \
  'Bowline does not execute provider requests once and only once.' \
  'Breaker state is process-local and does not survive restart or replicate.' \
  'Bowline has no route administration service.' \
  'Bowline has no built-in provider-specific integration.' \
  'Bowline does not scan prompts or block sensitive content.' \
  'Bowline does not isolate different customers inside one process.'; do
  if printf '%s\n' "$fixture" | has_unsupported_controlled_claim; then
    printf '%s\n' "controlled claim guard rejects factual boundary: $fixture" >&2
    failures=$((failures + 1))
  fi
done
if printf '%s\n' "$controlled_text" | has_unsupported_controlled_claim; then
  printf '%s\n' 'unsupported controlled-enforcement claim found' >&2
  failures=$((failures + 1))
fi

enforcement_examples='examples/enforcement/enforcement.killed.yaml
examples/enforcement/README.md
examples/enforcement/validate-offline.sh'
for file in $enforcement_examples; do
  if [ ! -f "$file" ]; then
    printf '%s\n' "missing synthetic controlled-enforcement example: $file" >&2
    failures=$((failures + 1))
  elif ! grep -Fiq 'synthetic' "$file"; then
    printf '%s\n' "controlled-enforcement example is not explicitly synthetic: $file" >&2
    failures=$((failures + 1))
  fi
done
if [ -f examples/enforcement/enforcement.killed.yaml ]; then
  grep -Fq 'mode: canary-enforce' examples/enforcement/enforcement.killed.yaml || failures=$((failures + 1))
  grep -Fq 'rollout_ppm:' examples/enforcement/enforcement.killed.yaml || failures=$((failures + 1))
  if grep -Eiq 'https?://[^[:space:]]+' examples/enforcement/enforcement.killed.yaml && \
    grep -Ev '^[[:space:]]*#' examples/enforcement/enforcement.killed.yaml | \
      grep -E 'https?://' | grep -Evq 'https?://(127\.0\.0\.1|localhost)(:|/)'; then
    printf '%s\n' 'controlled-enforcement example contains a non-loopback endpoint' >&2
    failures=$((failures + 1))
  fi
fi
if [ -f examples/enforcement/validate-offline.sh ] && \
  grep -Eiq '(^|[[:space:]])(curl|wget|nc|ncat|socat)([[:space:]]|$)' examples/enforcement/validate-offline.sh; then
  printf '%s\n' 'offline enforcement validator contains a network client' >&2
  failures=$((failures + 1))
fi

economics_text=$(printf '%s' "$public_markdown_text" | tr '\n' ' ')
for claim in \
  'Dimensions are reporting group keys, not tenant boundaries, authorization scopes, or secure isolation.' \
  'Billing evidence is operator-supplied input, not provider-authenticated truth.' \
  'Annualization is arithmetic over the declared past window using 31,556,952,000 milliseconds per year; it is not a forecast.' \
  'Opportunities are counterfactual modeled evidence, not realized savings.' \
  'Quality report schema v1 remains verifiable but is non-joinable for economics; schema v2 requires the exact workload, task, protocol, and candidate identity.' \
  'The bundle manifest binds six payload artifacts and excludes itself.' \
  'One deployment represents one enterprise security domain.'; do
  if ! printf '%s' "$economics_text" | grep -Fq "$claim"; then
    printf '%s\n' "required actionable-economics claim is missing: $claim" >&2
    failures=$((failures + 1))
  fi
done

if grep -R -n -Ei \
  'is provider-authenticated (billing )?(truth|evidence)|provides universal quality|forecasts savings|guarantees savings|delivers realized savings|automatically (promotes|routes|enforces)|provides provider-native (billing )?adapters|provides (a )?persistent analytics|provides (an )?analytics dashboard|provides secure multi-tenan|automatically approves spend' \
  README.md SUPPORT.md docs; then
  printf '%s\n' 'unsupported actionable-economics claim found' >&2
  failures=$((failures + 1))
fi

economics_examples='examples/billing/canonical.jsonl
examples/billing/mapped.csv
examples/billing/mapping.yaml
examples/economics/analysis.yaml'
for file in $economics_examples; do
  if [ ! -f "$file" ]; then
    printf '%s\n' "missing synthetic actionable-economics example: $file" >&2
    failures=$((failures + 1))
  elif ! grep -Fiq 'synthetic' "$file"; then
    printf '%s\n' "actionable-economics example is not explicitly synthetic: $file" >&2
    failures=$((failures + 1))
  fi
done

quality_text=$(printf '%s' "$public_markdown_text" | tr '\n' ' ')
for quality_claim in \
  'Quality canaries are an offline foreground process and do not mirror or replay live traffic.' \
  'Each candidate/case request and judge evaluation is dispatched at most once; Bowline does not retry.' \
  'Observed token and cost ceilings are continuation limits, not hard pre-dispatch currency reservations.' \
  'Candidate and judge endpoints receive transient customer-controlled content only when configured by the operator.' \
  'Persisted quality evidence contains no raw prompt, response, expected value, schema, regex, tool arguments, rubric, or judge prose.' \
  'Quality overlays are advisory evidence for one exact supply and do not mutate registry ratings, rank candidates, promote, route, or enforce.' \
  'A subjective judge is an explicitly configured model opinion, not ground truth or cryptographic attestation.' \
  'Dataset representativeness, spend authorization, governance approval, and quality acceptance remain external gates.'; do
  if ! printf '%s' "$quality_text" | grep -Fq "$quality_claim"; then
    printf '%s\n' "required customer-quality claim is missing: $quality_claim" >&2
    failures=$((failures + 1))
  fi
done

if grep -R -n -Ei \
  'universal quality score|ground-truth quality|mirrors live traffic|replays primary traffic|hard spend budget|guarantees spend|automatic promotion|automatically promotes|automatically routes|native provider support|cryptographically trusted judge|proves representativeness|persists raw prompts|stores raw responses|multi-tenant isolation' \
  README.md SUPPORT.md docs; then
  printf '%s\n' 'unsupported customer-quality claim found' >&2
  failures=$((failures + 1))
fi

quality_examples='examples/canary/canary.yaml
examples/canary/cases.jsonl
examples/canary/dataset.yaml
examples/canary/evaluators.yaml
examples/canary/rubric.md'
for file in $quality_examples; do
  if [ ! -f "$file" ]; then
    printf '%s\n' "missing synthetic quality example: $file" >&2
    failures=$((failures + 1))
  elif ! grep -Fiq 'synthetic' "$file"; then
    printf '%s\n' "quality example is not explicitly synthetic: $file" >&2
    failures=$((failures + 1))
  fi
done

litellm_namespace=$(sed -n 's/^attribution_namespace: //p' integrations/litellm/profile.yaml)
envoy_namespace=$(sed -n 's/^attribution_namespace: //p' integrations/envoy/profile.yaml)
quickstart_namespace=$(awk '
  /^attribution:$/ { attribution = 1; next }
  attribution && /^  namespace:/ { print $2; exit }
' docs/quickstart.md)
if [ -z "$litellm_namespace" ] || [ "$litellm_namespace" != "$envoy_namespace" ] || \
  [ "$litellm_namespace" != "$quickstart_namespace" ]; then
  printf '%s\n' \
    "attribution namespace drift: LiteLLM=$litellm_namespace Envoy=$envoy_namespace quickstart=$quickstart_namespace" >&2
  failures=$((failures + 1))
fi

obsolete_enforcement='Bowline is policy enforcement over workload identity'
if grep -R -Fq "$obsolete_enforcement" README.md docs; then
  printf '%s\n' 'obsolete present-tense policy-enforcement claim found' >&2
  failures=$((failures + 1))
fi

for factual_claim in \
  'Bowline evaluates workload-identity policy and records the resulting shadow decision.' \
  'does not hold routing enforcement authority.' \
  'It is not DLP.'; do
  if ! grep -R -Fq "$factual_claim" README.md docs; then
    printf '%s\n' "required shadow-mode policy claim is missing: $factual_claim" >&2
    failures=$((failures + 1))
  fi
done

for passive_claim in \
  'One deployment represents one enterprise security domain.' \
  'Passive import stays off the request path and has no routing authority.' \
  'The LiteLLM serializer is tested only against Bowline synthetic callback objects.' \
  'Envoy verification covers formatter, fixture, and profile key/type parity; it does not run a live Envoy process.' \
  'The pointer denylist cannot detect a secret aliased under an innocuous key.' \
  'Cross-run duplicate suppression is not performed.' \
  'Passive metadata is not cryptographically authenticated.'; do
  if ! grep -R -Fq "$passive_claim" README.md docs integrations; then
    printf '%s\n' "required passive-intake claim is missing: $passive_claim" >&2
    failures=$((failures + 1))
  fi
done

for false_claim in \
  'Bowline provides cryptographic provenance' \
  'Bowline automatically discovers LiteLLM logs' \
  'Bowline automatically discovers Envoy logs' \
  'Bowline runs a passive collector'; do
  if grep -R -Fiq "$false_claim" README.md docs integrations; then
    printf '%s\n' "unsupported public claim found: $false_claim" >&2
    failures=$((failures + 1))
  fi
done

for file in $required_docs deploy/kubernetes/README.md; do
  base=$(dirname "$file")
  links=$(perl -ne 'while (/\]\(([^)]+)\)/g) { print "$1\n" }' "$file")
  old_ifs=$IFS
  IFS='
'
  for link in $links; do
    case "$link" in
      http://*|https://*|mailto:*|\#*|'') continue ;;
    esac
    target=${link%%#*}
    if [ ! -e "$base/$target" ]; then
      printf '%s\n' "broken relative link in $file: $link" >&2
      failures=$((failures + 1))
    fi
  done
  IFS=$old_ifs
done

[ "$failures" -eq 0 ] || exit 1
printf '%s\n' 'documentation contract: PASS'
