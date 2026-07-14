use bowline_core::economics::CostRateMicros;

#[test]
fn exact_integer_rates_recompute_positive_zero_and_negative_delta() {
    let usage = (1_000_000, 1_000_000);
    for (candidate_rate, baseline_rate, expected) in [
        (1_000_000, 2_000_000, 2_000_000i128),
        (1_000_000, 1_000_000, 0),
        (2_000_000, 1_000_000, -2_000_000),
    ] {
        let candidate = CostRateMicros {
            input_per_mtok_micros: candidate_rate,
            output_per_mtok_micros: candidate_rate,
        }
        .cost_micros(usage.0, usage.1)
        .unwrap();
        let baseline = CostRateMicros {
            input_per_mtok_micros: baseline_rate,
            output_per_mtok_micros: baseline_rate,
        }
        .cost_micros(usage.0, usage.1)
        .unwrap();
        assert_eq!(i128::from(baseline) - i128::from(candidate), expected);
    }
}

#[test]
fn public_core_has_no_forgeable_authority_completeness_or_rate_input() {
    let source = include_str!("../src/economics.rs");
    assert!(!source.contains("EnforcedModeledDeltaInput"));
    assert!(!source.contains("authority_run_complete: bool"));
    assert!(!source.contains("pub fn enforced_modeled_delta("));
}
