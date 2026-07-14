# Contributing to Bowline

Thank you for improving Bowline. Start with an issue for behavior or architecture changes; small
documentation and test corrections may go directly to a pull request.

## Development

Use Rust 1.95 or newer and Docker Compose v2. Keep the default no-enforcement path byte-faithful and
shadow-only. Controlled-authority changes must remain explicit, exact, single-dispatch,
evidence-bound, and covered by focused tests. Add a failing test before behavior changes, preserve
the single-writer evidence contract, and update public documentation when a field, command, metric,
or non-claim changes.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
./scripts/check-docs.sh
./scripts/check-deployment.sh
./scripts/check-repo.sh
./scripts/docker-smoke.sh
```

Pull requests should be focused, explain user-visible impact and evidence migration, include tests,
and pass every gate. Never include credentials, customer data, partner names, private strategy, or
generated `target`/ledger artifacts.

## License and inbound contributions

The project is Apache-2.0. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion is provided under Apache-2.0, without a Contributor License Agreement.
You represent that you have the right to submit it. Sign-off is not currently required.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately using
[SECURITY](SECURITY.md), not through a public issue.
