# Shadow-run against local Ollama

Run Bowline in shadow mode in front of an [Ollama](https://ollama.com) server: real local
inference through the passthrough, real usage accounted in the ledger, a real report at the
end. This is the fastest way to see the full loop on hardware you own — no provider account
needed.

## Prerequisites

- Ollama running (`ollama serve`) with at least one model pulled. The example feed maps
  `qwen3:8b`; edit the `model` field of the `local/ollama-model` entry in
  `feed.ollama.json` to match a model you have (`ollama list`).
- The feed treats the Ollama model as `owned` supply with no feed price — owned supply is
  priced through your declared TCO inputs (`tco.example.yaml`), never through the feed.

## Native

From the workspace root:

```sh
cargo run -p bowline -- serve --config examples/ollama/bowline.ollama.yaml
```

Send traffic through the gateway (same request shapes as the quickstart — plain,
workload-identified, streaming), substituting your model name:

```sh
client_id=synthetic-local-client
curl -sS http://127.0.0.1:8091/v1/chat/completions \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $client_id" \
  -d '{"model": "qwen3:8b", "messages": [{"role": "user", "content": "Say ok."}]}'
```

Then render the report:

```sh
cargo run -p bowline -- report --config examples/ollama/bowline.ollama.yaml
```

## Docker

Containerized gateway, Ollama stays on the host:

```sh
docker compose -f examples/ollama/compose.yml up --build -d
client_id=synthetic-local-client
curl -sS http://127.0.0.1:8092/v1/chat/completions \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $client_id" \
  -d '{"model": "qwen3:8b", "messages": [{"role": "user", "content": "Say ok."}]}'
docker compose -f examples/ollama/compose.yml run --rm bowline-ollama report --config /config/bowline.yaml
docker compose -f examples/ollama/compose.yml down -v
```

## What to expect

With only owned supply taking traffic, the report shows a 100% actual owned ratio; the
counterfactual compares against the frontier reference in the feed. Very small runs price
below one cent, so cost cells can render as $0.00 — send a realistic volume before reading
anything into the numbers. Bowline observes and accounts; it changes no routing in shadow
mode.
