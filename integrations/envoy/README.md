# Envoy typed-JSON output contract

`typed-json-access-log.yaml` is an exact configuration example for the safe scalar contract consumed
by `profile.yaml`. The fixture and Rust parity test validate the declared keys and scalar types.

This repository does not claim a live Envoy runtime test. Envoy does not derive model attribution or
LLM token usage by itself; the operator must explicitly provide those values as reviewed dynamic
metadata. Do not add prompts, bodies, arbitrary headers, credentials, or raw URLs to the formatter.

Envoy verification covers formatter, fixture, and profile key/type parity; it does not run a live Envoy process.
The example is not a universal or native Envoy LLM log schema.
