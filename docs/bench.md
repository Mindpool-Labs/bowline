# Bowline Latency Bench

## Method

The bench starts an OpenAI-compatible echo upstream in-process on localhost and measures sequential
`/v1/chat/completions` POSTs with a reused HTTP client. It first measures direct echo latency, then
starts the Bowline gateway in shadow mode with a temporary bounded segmented ledger plus
`policies/default.yaml` and `registry/feed.json`, and measures the same request path through the
gateway. The benchmark drains the managed writer before printing its run ID and reconciliation
counters, so the latency result and durable evidence describe the same run.

Run in release mode on localhost. Results from a developer laptop are useful for regression checks,
but deployment evidence should be re-run on your deployment host.

## Run

```sh
cargo run -p bowline-gateway --release --bin bowline-bench
```

Use `-- --allow-fail` to print numbers without making the process fail when the budget is missed.

## Design Budget

Bowline's Phase 1 design budget is less than 5 ms p95 added latency for the deterministic gateway
path. This bench measures the hot proxy path only; decision ledger writes are off-path and should not
be included in the client-observed p95 budget except for queueing overhead.

## Results

Measured 2026-07-10, release build, Apple Silicon developer laptop (macOS), in-process localhost,
500 requests after 25-request warmup:

```
direct_echo     p50=0.074ms  p95=0.091ms  p99=0.101ms
gateway_shadow  p50=0.081ms  p95=0.099ms  p99=0.107ms
added_delta     p50=0.007ms  p95=0.008ms  p99=0.006ms
evidence        accepted=525 recorded=525 dropped=0 truncated=0
budget added_p95<5.000ms PASS
```

The added deltas are distribution differences (sorted percentile minus sorted percentile), not
per-request pairs. On pooled loopback connections the deterministic shadow path (identity
extraction + policy evaluation + decision) adds single-digit microseconds at the median, well
inside the 5 ms budget. Re-run on your deployment host for numbers that include real network
stacks.
