use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::supply::Registry;

pub const BILLING_SCHEMA_VERSION: u32 = 1;
pub const MAX_BILLING_ROWS: usize = 100_000;
pub const MAX_BILLING_IDENTIFIER_BYTES: usize = 128;
pub const MAX_BILLING_TIMESTAMP_MS: u64 = 253_402_300_799_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChargeBasis {
    InferenceUsageNet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BillingCurrency {
    USD,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UsdMicros(u64);

impl UsdMicros {
    pub fn parse(value: &str) -> Result<Self, BillingError> {
        if value.is_empty() || value.starts_with(['+', '-']) || value.contains(['e', 'E']) {
            return Err(BillingError::InvalidMoney);
        }
        let (whole, fraction) = match value.split_once('.') {
            Some((whole, fraction)) if !fraction.is_empty() && fraction.len() <= 6 => {
                (whole, fraction)
            }
            Some(_) => return Err(BillingError::InvalidMoney),
            None => (value, ""),
        };
        if whole.is_empty()
            || (whole.len() > 1 && whole.starts_with('0'))
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(BillingError::InvalidMoney);
        }
        let whole = whole
            .parse::<u64>()
            .map_err(|_| BillingError::InvalidMoney)?;
        let fraction = if fraction.is_empty() {
            0
        } else {
            fraction
                .parse::<u64>()
                .map_err(|_| BillingError::InvalidMoney)?
                .checked_mul(10u64.pow(6 - fraction.len() as u32))
                .ok_or(BillingError::InvalidMoney)?
        };
        whole
            .checked_mul(1_000_000)
            .and_then(|value| value.checked_add(fraction))
            .map(Self)
            .ok_or(BillingError::InvalidMoney)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingInputRow {
    pub schema_version: u32,
    pub row_id: String,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub supply_id: String,
    pub currency: String,
    pub charge_basis: String,
    pub charge_usd: String,
    pub request_count: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingRow {
    pub schema_version: u32,
    pub row_id: String,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub supply_id: String,
    pub currency: BillingCurrency,
    pub charge_basis: ChargeBasis,
    pub charge_usd_micros: UsdMicros,
    pub request_count: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingTotals {
    pub rows: u64,
    pub charge_usd_micros: u64,
    pub request_count: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBilling {
    rows: Vec<BillingRow>,
    totals: BillingTotals,
    canonical_digest: String,
}

impl ValidatedBilling {
    pub fn rows(&self) -> &[BillingRow] {
        &self.rows
    }
    pub fn totals(&self) -> &BillingTotals {
        &self.totals
    }
    pub fn canonical_digest(&self) -> &str {
        &self.canonical_digest
    }
}

pub fn validate_billing_rows(
    rows: Vec<BillingInputRow>,
    registry: &Registry,
) -> Result<ValidatedBilling, BillingError> {
    if rows.is_empty() || rows.len() > MAX_BILLING_ROWS {
        return Err(BillingError::RowLimit);
    }
    let mut ids = HashSet::with_capacity(rows.len());
    let mut normalized = Vec::with_capacity(rows.len());
    for row in rows {
        if row.schema_version != BILLING_SCHEMA_VERSION {
            return Err(BillingError::UnsupportedSchema(row.schema_version));
        }
        if !safe_id(&row.row_id) || !ids.insert(row.row_id.clone()) {
            return Err(BillingError::InvalidRowId);
        }
        if row.supply_id.is_empty()
            || row.supply_id.len() > MAX_BILLING_IDENTIFIER_BYTES
            || registry.by_id(&row.supply_id).is_none()
        {
            return Err(BillingError::UnknownSupply(row.supply_id));
        }
        if row.period_end_ms <= row.period_start_ms || row.period_end_ms > MAX_BILLING_TIMESTAMP_MS
        {
            return Err(BillingError::InvalidWindow);
        }
        if row.currency != "USD" {
            return Err(BillingError::InvalidCurrency);
        }
        if row.charge_basis != "inference-usage-net" {
            return Err(BillingError::InvalidChargeBasis);
        }
        normalized.push(BillingRow {
            schema_version: BILLING_SCHEMA_VERSION,
            row_id: row.row_id,
            period_start_ms: row.period_start_ms,
            period_end_ms: row.period_end_ms,
            supply_id: row.supply_id,
            currency: BillingCurrency::USD,
            charge_basis: ChargeBasis::InferenceUsageNet,
            charge_usd_micros: UsdMicros::parse(&row.charge_usd)?,
            request_count: row.request_count,
            input_tokens: row.input_tokens,
            output_tokens: row.output_tokens,
        });
    }
    let mut by_supply: BTreeMap<&str, Vec<&BillingRow>> = BTreeMap::new();
    for row in &normalized {
        by_supply.entry(&row.supply_id).or_default().push(row);
    }
    for rows in by_supply.values_mut() {
        rows.sort_by_key(|row| (row.period_start_ms, row.period_end_ms, row.row_id.as_str()));
        if rows
            .windows(2)
            .any(|pair| pair[1].period_start_ms < pair[0].period_end_ms)
        {
            return Err(BillingError::OverlappingRows);
        }
    }
    normalized.sort_by(|left, right| {
        (
            left.period_start_ms,
            left.period_end_ms,
            left.supply_id.as_str(),
            left.row_id.as_str(),
        )
            .cmp(&(
                right.period_start_ms,
                right.period_end_ms,
                right.supply_id.as_str(),
                right.row_id.as_str(),
            ))
    });
    let totals = totals(&normalized)?;
    let canonical_digest = digest_rows(&normalized)?;
    Ok(ValidatedBilling {
        rows: normalized,
        totals,
        canonical_digest,
    })
}

pub fn validate_normalized_rows(rows: Vec<BillingRow>) -> Result<ValidatedBilling, BillingError> {
    if rows.is_empty() || rows.len() > MAX_BILLING_ROWS {
        return Err(BillingError::RowLimit);
    }
    let mut ids = HashSet::new();
    for row in &rows {
        if row.schema_version != BILLING_SCHEMA_VERSION
            || !safe_id(&row.row_id)
            || !ids.insert(row.row_id.as_str())
            || row.period_end_ms <= row.period_start_ms
            || row.period_end_ms > MAX_BILLING_TIMESTAMP_MS
            || row.supply_id.is_empty()
            || row.supply_id.len() > MAX_BILLING_IDENTIFIER_BYTES
            || row.currency != BillingCurrency::USD
            || row.charge_basis != ChargeBasis::InferenceUsageNet
        {
            return Err(BillingError::InvalidNormalizedRow);
        }
    }
    for pair in rows.windows(2) {
        let left_key = (
            pair[0].period_start_ms,
            pair[0].period_end_ms,
            pair[0].supply_id.as_str(),
            pair[0].row_id.as_str(),
        );
        let right_key = (
            pair[1].period_start_ms,
            pair[1].period_end_ms,
            pair[1].supply_id.as_str(),
            pair[1].row_id.as_str(),
        );
        if left_key >= right_key {
            return Err(BillingError::InvalidNormalizedRow);
        }
    }
    let mut previous: BTreeMap<&str, u64> = BTreeMap::new();
    for row in &rows {
        if previous
            .get(row.supply_id.as_str())
            .is_some_and(|end| row.period_start_ms < *end)
        {
            return Err(BillingError::OverlappingRows);
        }
        previous.insert(&row.supply_id, row.period_end_ms);
    }
    let totals = totals(&rows)?;
    let canonical_digest = digest_rows(&rows)?;
    Ok(ValidatedBilling {
        rows,
        totals,
        canonical_digest,
    })
}

fn totals(rows: &[BillingRow]) -> Result<BillingTotals, BillingError> {
    let mut charge = 0u64;
    let mut request = Some(0u64);
    let mut input = Some(0u64);
    let mut output = Some(0u64);
    for row in rows {
        charge = charge
            .checked_add(row.charge_usd_micros.get())
            .ok_or(BillingError::TotalOverflow)?;
        checked_optional_add(&mut request, row.request_count)?;
        checked_optional_add(&mut input, row.input_tokens)?;
        checked_optional_add(&mut output, row.output_tokens)?;
    }
    Ok(BillingTotals {
        rows: rows.len() as u64,
        charge_usd_micros: charge,
        request_count: request,
        input_tokens: input,
        output_tokens: output,
    })
}

fn checked_optional_add(total: &mut Option<u64>, value: Option<u64>) -> Result<(), BillingError> {
    *total = match (*total, value) {
        (Some(total), Some(value)) => Some(
            total
                .checked_add(value)
                .ok_or(BillingError::TotalOverflow)?,
        ),
        _ => None,
    };
    Ok(())
}

fn digest_rows(rows: &[BillingRow]) -> Result<String, BillingError> {
    let mut hasher = Sha256::new();
    frame(&mut hasher, b"bowline.billing.normalized.v1");
    for row in rows {
        frame(&mut hasher, &serde_json::to_vec(row)?);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    frame(&mut hasher, domain);
    frame(&mut hasher, bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BILLING_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("billing row limit violated")]
    RowLimit,
    #[error("unsupported billing schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid or duplicate billing row id")]
    InvalidRowId,
    #[error("unknown billing supply: {0}")]
    UnknownSupply(String),
    #[error("invalid billing period")]
    InvalidWindow,
    #[error("billing currency must be USD")]
    InvalidCurrency,
    #[error("charge basis must be inference-usage-net")]
    InvalidChargeBasis,
    #[error("invalid exact USD decimal")]
    InvalidMoney,
    #[error("billing rows overlap for one supply")]
    OverlappingRows,
    #[error("billing totals overflow")]
    TotalOverflow,
    #[error("invalid normalized billing row")]
    InvalidNormalizedRow,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply::Registry;

    fn registry() -> Registry {
        Registry::from_json(r#"{"feed_version":"fixture","entries":[{"id":"public/east","model":"model","location":"fixture","attributes":{"class":"public-api","jurisdiction":"us","retention":"unknown","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}}]}"#).unwrap()
    }

    fn row(id: &str, start: u64, end: u64, charge: &str) -> BillingInputRow {
        BillingInputRow {
            schema_version: 1,
            row_id: id.into(),
            period_start_ms: start,
            period_end_ms: end,
            supply_id: "public/east".into(),
            currency: "USD".into(),
            charge_basis: "inference-usage-net".into(),
            charge_usd: charge.into(),
            request_count: None,
            input_tokens: None,
            output_tokens: None,
        }
    }

    #[test]
    fn usd_decimal_is_exact_checked_and_canonical() {
        for (source, micros) in [
            ("0", 0),
            ("12", 12_000_000),
            ("0.000001", 1),
            ("123.456789", 123_456_789),
        ] {
            assert_eq!(UsdMicros::parse(source).unwrap().get(), micros);
        }
        for invalid in [
            "",
            "+1",
            "-1",
            "1.",
            ".1",
            "01",
            "1.0000000",
            "1e2",
            "NaN",
            "18446744073709.551616",
        ] {
            assert!(UsdMicros::parse(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn validates_strict_rows_registry_order_overlap_and_absent_counts() {
        let rows = vec![row("later", 20, 30, "2"), row("first", 0, 20, "1.25")];
        let normalized = validate_billing_rows(rows, &registry()).unwrap();
        assert_eq!(normalized.rows()[0].row_id, "first");
        assert_eq!(normalized.totals().charge_usd_micros, 3_250_000);
        assert_eq!(normalized.totals().request_count, None);
        assert_eq!(normalized.totals().input_tokens, None);
        assert_eq!(normalized.totals().output_tokens, None);
        assert!(normalized.canonical_digest().starts_with("sha256:"));

        let mut overlapping = vec![row("a", 0, 20, "1"), row("b", 19, 30, "1")];
        assert!(validate_billing_rows(overlapping.clone(), &registry()).is_err());
        overlapping[1].period_start_ms = 20;
        assert!(validate_billing_rows(overlapping, &registry()).is_ok());
    }

    #[test]
    fn rejects_wrong_schema_ids_supply_currency_basis_windows_and_count_overflow() {
        let mut cases = Vec::new();
        let mut value = row("ok", 0, 1, "1");
        value.schema_version = 2;
        cases.push(value);
        let value = row("bad/id", 0, 1, "1");
        cases.push(value);
        let mut value = row("ok", 0, 1, "1");
        value.supply_id = "unknown".into();
        cases.push(value);
        let mut value = row("ok", 0, 1, "1");
        value.currency = "EUR".into();
        cases.push(value);
        let mut value = row("ok", 0, 1, "1");
        value.charge_basis = "gross".into();
        cases.push(value);
        let value = row("ok", 1, 1, "1");
        cases.push(value);
        let value = row("ok", 0, MAX_BILLING_TIMESTAMP_MS + 1, "1");
        cases.push(value);
        for value in cases {
            assert!(validate_billing_rows(vec![value], &registry()).is_err());
        }

        let mut a = row("a", 0, 1, "1");
        a.request_count = Some(u64::MAX);
        let mut b = row("b", 1, 2, "1");
        b.request_count = Some(1);
        assert!(validate_billing_rows(vec![a, b], &registry()).is_err());
    }

    #[test]
    fn digest_is_domain_separated_length_framed_and_content_free() {
        let a = validate_billing_rows(vec![row("ab", 0, 1, "1")], &registry()).unwrap();
        let b = validate_billing_rows(vec![row("a", 0, 1, "1"), row("b", 1, 2, "1")], &registry())
            .unwrap();
        assert_ne!(a.canonical_digest(), b.canonical_digest());
        let json = serde_json::to_string(a.rows()).unwrap();
        for forbidden in [
            "prompt",
            "response",
            "authorization",
            "user_identity",
            "source_path",
            "raw_csv",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
