use std::collections::HashSet;

use bowline_core::{
    billing::{
        domain_digest, validate_billing_rows, BillingInputRow, ValidatedBilling, MAX_BILLING_ROWS,
    },
    billing_run::{BillingProvenance, BillingSourceFormat},
    supply::Registry,
};
use csv::{ReaderBuilder, StringRecord};
use serde::Deserialize;
use thiserror::Error;

pub const MAX_BILLING_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BILLING_ROW_BYTES: usize = 16 * 1024;
pub const MAX_MAPPING_BYTES: usize = 64 * 1024;
pub const MAX_CSV_COLUMNS: usize = 128;
pub const MAX_CSV_FIELD_BYTES: usize = 4096;
pub const MAX_CSV_HEADER_BYTES: usize = 256;
pub const MAX_REGISTRY_BYTES: usize = 16 * 1024 * 1024;

pub struct ParsedBilling {
    pub validated: ValidatedBilling,
    pub provenance: BillingProvenance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CsvMapping {
    version: u32,
    delimiter: Delimiter,
    columns: CsvColumns,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Delimiter {
    Comma,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CsvColumns {
    row_id: String,
    period_start_ms: String,
    period_end_ms: String,
    supply_id: String,
    currency: String,
    charge_basis: String,
    charge_usd: String,
    #[serde(default)]
    request_count: Option<String>,
    #[serde(default)]
    input_tokens: Option<String>,
    #[serde(default)]
    output_tokens: Option<String>,
}

pub fn parse_canonical_jsonl(
    source: &[u8],
    registry_source: &[u8],
    registry: &Registry,
) -> Result<ParsedBilling, BillingParseError> {
    validate_registry_source(registry_source)?;
    validate_input(source)?;
    let text = std::str::from_utf8(source).map_err(|_| BillingParseError::Utf8)?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.len() > MAX_BILLING_ROW_BYTES {
            return Err(BillingParseError::RowLimit);
        }
        if rows.len() >= MAX_BILLING_ROWS {
            return Err(BillingParseError::RowCount);
        }
        rows.push(serde_json::from_str::<BillingInputRow>(line)?);
    }
    finish(
        rows,
        registry,
        BillingSourceFormat::CanonicalJsonl,
        domain_digest(b"bowline.billing.source.canonical-jsonl.v1", source),
        None,
        registry_source,
    )
}

pub fn parse_mapped_csv(
    source: &[u8],
    mapping_source: &[u8],
    registry_source: &[u8],
    registry: &Registry,
) -> Result<ParsedBilling, BillingParseError> {
    validate_registry_source(registry_source)?;
    validate_input(source)?;
    validate_rfc4180(source)?;
    if mapping_source.is_empty() || mapping_source.len() > MAX_MAPPING_BYTES {
        return Err(BillingParseError::MappingLimit);
    }
    std::str::from_utf8(mapping_source).map_err(|_| BillingParseError::Utf8)?;
    let mapping: CsvMapping = serde_yaml::from_slice(mapping_source)?;
    if mapping.version != 1 || mapping.delimiter != Delimiter::Comma {
        return Err(BillingParseError::InvalidMapping);
    }
    validate_mapping(&mapping.columns)?;
    let mut reader = ReaderBuilder::new()
        .delimiter(b',')
        .has_headers(true)
        .flexible(false)
        .from_reader(source);
    let headers = reader.headers()?.clone();
    validate_headers(&headers)?;
    let indices = MappingIndices::resolve(&headers, &mapping.columns)?;
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record?;
        if rows.len() >= MAX_BILLING_ROWS {
            return Err(BillingParseError::RowCount);
        }
        validate_record(&record)?;
        rows.push(indices.row(&record)?);
    }
    finish(
        rows,
        registry,
        BillingSourceFormat::MappedCsv,
        domain_digest(b"bowline.billing.source.mapped-csv.v1", source),
        Some(domain_digest(b"bowline.billing.mapping.v1", mapping_source)),
        registry_source,
    )
}

fn finish(
    rows: Vec<BillingInputRow>,
    registry: &Registry,
    source_format: BillingSourceFormat,
    source_digest: String,
    mapping_digest: Option<String>,
    registry_source: &[u8],
) -> Result<ParsedBilling, BillingParseError> {
    let registry_text =
        std::str::from_utf8(registry_source).map_err(|_| BillingParseError::Utf8)?;
    let bound_registry = Registry::from_json(registry_text)
        .map_err(|error| BillingParseError::InvalidRegistry(error.to_string()))?;
    if serde_json::to_vec(&bound_registry)? != serde_json::to_vec(registry)? {
        return Err(BillingParseError::RegistryMismatch);
    }
    let validated = validate_billing_rows(rows, registry)?;
    let provenance = BillingProvenance {
        source_format,
        source_digest,
        mapping_digest,
        registry_digest: registry_file_digest(registry_source),
        charge_basis: bowline_core::billing::ChargeBasis::InferenceUsageNet,
    };
    provenance.validate()?;
    Ok(ParsedBilling {
        validated,
        provenance,
    })
}

pub fn registry_file_digest(source: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(source))
}

fn validate_input(source: &[u8]) -> Result<(), BillingParseError> {
    if source.is_empty() || source.len() > MAX_BILLING_INPUT_BYTES {
        Err(BillingParseError::InputLimit)
    } else {
        Ok(())
    }
}

fn validate_registry_source(source: &[u8]) -> Result<(), BillingParseError> {
    if source.is_empty() || source.len() > MAX_REGISTRY_BYTES {
        Err(BillingParseError::RegistryLimit)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CsvLexState {
    FieldStart,
    Unquoted,
    Quoted,
    AfterQuote,
}

fn validate_rfc4180(source: &[u8]) -> Result<(), BillingParseError> {
    let mut state = CsvLexState::FieldStart;
    let mut offset = 0usize;
    let mut record_bytes = 0usize;
    while offset < source.len() {
        let byte = source[offset];
        add_record_byte(&mut record_bytes)?;
        match state {
            CsvLexState::FieldStart => match byte {
                b',' => {}
                b'"' => state = CsvLexState::Quoted,
                b'\r' => consume_record_end(source, &mut offset, &mut record_bytes)?,
                b'\n' => return Err(BillingParseError::MalformedCsv),
                _ if prohibited_unquoted(byte) => return Err(BillingParseError::MalformedCsv),
                _ => state = CsvLexState::Unquoted,
            },
            CsvLexState::Unquoted => match byte {
                b',' => state = CsvLexState::FieldStart,
                b'"' => return Err(BillingParseError::MalformedCsv),
                b'\r' => {
                    consume_record_end(source, &mut offset, &mut record_bytes)?;
                    state = CsvLexState::FieldStart;
                }
                b'\n' => return Err(BillingParseError::MalformedCsv),
                _ if prohibited_unquoted(byte) => return Err(BillingParseError::MalformedCsv),
                _ => {}
            },
            CsvLexState::Quoted => match byte {
                b'"' => state = CsvLexState::AfterQuote,
                b'\r' => consume_quoted_line_end(source, &mut offset, &mut record_bytes)?,
                b'\n' => return Err(BillingParseError::MalformedCsv),
                _ if prohibited_unquoted(byte) => return Err(BillingParseError::MalformedCsv),
                _ => {}
            },
            CsvLexState::AfterQuote => match byte {
                b'"' => state = CsvLexState::Quoted,
                b',' => state = CsvLexState::FieldStart,
                b'\r' => {
                    consume_record_end(source, &mut offset, &mut record_bytes)?;
                    state = CsvLexState::FieldStart;
                }
                _ => return Err(BillingParseError::MalformedCsv),
            },
        }
        offset += 1;
    }
    if matches!(state, CsvLexState::Quoted) {
        return Err(BillingParseError::MalformedCsv);
    }
    Ok(())
}

fn add_record_byte(record_bytes: &mut usize) -> Result<(), BillingParseError> {
    *record_bytes = record_bytes
        .checked_add(1)
        .ok_or(BillingParseError::RowLimit)?;
    if *record_bytes > MAX_BILLING_ROW_BYTES {
        return Err(BillingParseError::RowLimit);
    }
    Ok(())
}

fn consume_record_end(
    source: &[u8],
    offset: &mut usize,
    record_bytes: &mut usize,
) -> Result<(), BillingParseError> {
    if *record_bytes == 1 {
        return Err(BillingParseError::MalformedCsv);
    }
    if source.get(*offset + 1) != Some(&b'\n') {
        return Err(BillingParseError::MalformedCsv);
    }
    add_record_byte(record_bytes)?;
    *offset += 1;
    *record_bytes = 0;
    Ok(())
}

fn prohibited_unquoted(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

fn consume_quoted_line_end(
    source: &[u8],
    offset: &mut usize,
    record_bytes: &mut usize,
) -> Result<(), BillingParseError> {
    if source.get(*offset + 1) != Some(&b'\n') {
        return Err(BillingParseError::MalformedCsv);
    }
    add_record_byte(record_bytes)?;
    *offset += 1;
    Ok(())
}

fn validate_mapping(columns: &CsvColumns) -> Result<(), BillingParseError> {
    let required = [
        &columns.row_id,
        &columns.period_start_ms,
        &columns.period_end_ms,
        &columns.supply_id,
        &columns.currency,
        &columns.charge_basis,
        &columns.charge_usd,
    ];
    let mut seen = HashSet::new();
    for name in required.into_iter().chain(
        [
            columns.request_count.as_ref(),
            columns.input_tokens.as_ref(),
            columns.output_tokens.as_ref(),
        ]
        .into_iter()
        .flatten(),
    ) {
        if name.is_empty() || name.len() > MAX_CSV_HEADER_BYTES || !seen.insert(name.as_str()) {
            return Err(BillingParseError::InvalidMapping);
        }
    }
    Ok(())
}

fn validate_headers(headers: &StringRecord) -> Result<(), BillingParseError> {
    if headers.is_empty() || headers.len() > MAX_CSV_COLUMNS {
        return Err(BillingParseError::HeaderLimit);
    }
    let mut seen = HashSet::new();
    for header in headers {
        if header.is_empty() || header.len() > MAX_CSV_HEADER_BYTES || !seen.insert(header) {
            return Err(BillingParseError::InvalidHeader);
        }
    }
    Ok(())
}

fn validate_record(record: &StringRecord) -> Result<(), BillingParseError> {
    for value in record {
        if value.len() > MAX_CSV_FIELD_BYTES {
            return Err(BillingParseError::FieldLimit);
        }
        if value.starts_with(['=', '+', '-', '@']) {
            return Err(BillingParseError::Formula);
        }
    }
    Ok(())
}

struct MappingIndices {
    row_id: usize,
    start: usize,
    end: usize,
    supply: usize,
    currency: usize,
    basis: usize,
    charge: usize,
    request: Option<usize>,
    input: Option<usize>,
    output: Option<usize>,
}

impl MappingIndices {
    fn resolve(headers: &StringRecord, c: &CsvColumns) -> Result<Self, BillingParseError> {
        let find = |name: &str| {
            headers
                .iter()
                .position(|header| header == name)
                .ok_or(BillingParseError::MissingColumn)
        };
        Ok(Self {
            row_id: find(&c.row_id)?,
            start: find(&c.period_start_ms)?,
            end: find(&c.period_end_ms)?,
            supply: find(&c.supply_id)?,
            currency: find(&c.currency)?,
            basis: find(&c.charge_basis)?,
            charge: find(&c.charge_usd)?,
            request: c.request_count.as_deref().map(find).transpose()?,
            input: c.input_tokens.as_deref().map(find).transpose()?,
            output: c.output_tokens.as_deref().map(find).transpose()?,
        })
    }
    fn row(&self, r: &StringRecord) -> Result<BillingInputRow, BillingParseError> {
        let field = |index| r.get(index).ok_or(BillingParseError::MissingColumn);
        let count = |index: Option<usize>| -> Result<Option<u64>, BillingParseError> {
            match index {
                None => Ok(None),
                Some(index) => {
                    let value = field(index)?;
                    if value.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(parse_u64(value)?))
                    }
                }
            }
        };
        Ok(BillingInputRow {
            schema_version: 1,
            row_id: field(self.row_id)?.to_owned(),
            period_start_ms: parse_u64(field(self.start)?)?,
            period_end_ms: parse_u64(field(self.end)?)?,
            supply_id: field(self.supply)?.to_owned(),
            currency: field(self.currency)?.to_owned(),
            charge_basis: field(self.basis)?.to_owned(),
            charge_usd: field(self.charge)?.to_owned(),
            request_count: count(self.request)?,
            input_tokens: count(self.input)?,
            output_tokens: count(self.output)?,
        })
    }
}

fn parse_u64(value: &str) -> Result<u64, BillingParseError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BillingParseError::NonCanonicalNumber);
    }
    value
        .parse()
        .map_err(|_| BillingParseError::NonCanonicalNumber)
}

#[derive(Debug, Error)]
pub enum BillingParseError {
    #[error("billing input exceeds byte bounds")]
    InputLimit,
    #[error("billing input is not UTF-8")]
    Utf8,
    #[error("registry source exceeds byte bounds")]
    RegistryLimit,
    #[error("invalid registry bytes: {0}")]
    InvalidRegistry(String),
    #[error("registry bytes do not match the supplied registry")]
    RegistryMismatch,
    #[error("billing row exceeds byte bounds")]
    RowLimit,
    #[error("billing row count exceeds bound")]
    RowCount,
    #[error("billing mapping exceeds byte bounds")]
    MappingLimit,
    #[error("invalid billing mapping")]
    InvalidMapping,
    #[error("CSV header exceeds bounds")]
    HeaderLimit,
    #[error("CSV header is empty or duplicated")]
    InvalidHeader,
    #[error("mapped CSV column is missing")]
    MissingColumn,
    #[error("CSV field exceeds byte bound")]
    FieldLimit,
    #[error("CSV formulas are forbidden")]
    Formula,
    #[error("CSV is not strict RFC 4180")]
    MalformedCsv,
    #[error("number is not canonical unsigned decimal")]
    NonCanonicalNumber,
    #[error(transparent)]
    Csv(#[from] csv::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Core(#[from] bowline_core::billing::BillingError),
    #[error(transparent)]
    Store(#[from] bowline_core::billing_run::BillingRunError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowline_core::supply::Registry;
    use sha2::{Digest, Sha256};

    const REGISTRY: &str = r#"{"feed_version":"fixture","entries":[{"id":"public/east","model":"model","location":"fixture","attributes":{"class":"public-api","jurisdiction":"us","retention":"unknown","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}}]}"#;
    fn registry() -> Registry {
        Registry::from_json(REGISTRY).unwrap()
    }
    const JSONL: &str = "{\"schema_version\":1,\"row_id\":\"row-1\",\"period_start_ms\":0,\"period_end_ms\":1,\"supply_id\":\"public/east\",\"currency\":\"USD\",\"charge_basis\":\"inference-usage-net\",\"charge_usd\":\"1.250000\",\"request_count\":null,\"input_tokens\":2,\"output_tokens\":3}\n";
    const MAPPING: &str = "version: 1\ndelimiter: comma\ncolumns:\n  row_id: rid\n  period_start_ms: start\n  period_end_ms: end\n  supply_id: supply\n  currency: currency\n  charge_basis: basis\n  charge_usd: charge\n  request_count: requests\n  input_tokens: inputs\n  output_tokens: outputs\n";
    const CSV: &str = "rid,start,end,supply,currency,basis,charge,requests,inputs,outputs,ignored\r\nrow-1,0,1,public/east,USD,inference-usage-net,1.250000,,2,3,x\r\n";

    #[test]
    fn canonical_jsonl_and_explicit_csv_mapping_normalize_identically() {
        let json =
            parse_canonical_jsonl(JSONL.as_bytes(), REGISTRY.as_bytes(), &registry()).unwrap();
        let csv = parse_mapped_csv(
            CSV.as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry(),
        )
        .unwrap();
        assert_eq!(json.validated.rows(), csv.validated.rows());
        assert_eq!(
            json.validated.canonical_digest(),
            csv.validated.canonical_digest()
        );
        assert_ne!(json.provenance.source_digest, csv.provenance.source_digest);
        assert!(json.provenance.mapping_digest.is_none());
        assert!(csv.provenance.mapping_digest.is_some());
    }

    #[test]
    fn registry_provenance_is_the_exact_raw_file_sha256_on_both_paths() {
        let json =
            parse_canonical_jsonl(JSONL.as_bytes(), REGISTRY.as_bytes(), &registry()).unwrap();
        let csv = parse_mapped_csv(
            CSV.as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry(),
        )
        .unwrap();
        let expected = format!("sha256:{:x}", Sha256::digest(REGISTRY.as_bytes()));
        assert_eq!(json.provenance.registry_digest, expected);
        assert_eq!(csv.provenance.registry_digest, expected);

        let formatted = format!("\n{REGISTRY}\n");
        let formatted_registry = Registry::from_json(&formatted).unwrap();
        let changed =
            parse_canonical_jsonl(JSONL.as_bytes(), formatted.as_bytes(), &formatted_registry)
                .unwrap();
        assert_eq!(
            changed.provenance.registry_digest,
            format!("sha256:{:x}", Sha256::digest(formatted.as_bytes()))
        );
        assert_ne!(changed.provenance.registry_digest, expected);

        let mismatched = Registry::from_json(&REGISTRY.replace("fixture", "different")).unwrap();
        assert!(parse_canonical_jsonl(JSONL.as_bytes(), REGISTRY.as_bytes(), &mismatched).is_err());
    }

    #[test]
    fn shipped_synthetic_fixtures_normalize_identically() {
        let json = parse_canonical_jsonl(
            include_bytes!("../tests/fixtures/billing/canonical.jsonl"),
            REGISTRY.as_bytes(),
            &registry(),
        )
        .unwrap();
        let csv = parse_mapped_csv(
            include_bytes!("../tests/fixtures/billing/generic.csv"),
            include_bytes!("../tests/fixtures/billing/mapping.yaml"),
            REGISTRY.as_bytes(),
            &registry(),
        )
        .unwrap();
        assert_eq!(json.validated.rows(), csv.validated.rows());
    }

    #[test]
    fn strict_jsonl_rejects_unknown_fields_bad_lines_and_bounds() {
        let unknown = JSONL.replace("\"request_count\"", "\"secret\":\"x\",\"request_count\"");
        assert!(
            parse_canonical_jsonl(unknown.as_bytes(), REGISTRY.as_bytes(), &registry()).is_err()
        );
        assert!(parse_canonical_jsonl(
            format!("{JSONL}not-json\n").as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_canonical_jsonl(
            &vec![b'x'; MAX_BILLING_INPUT_BYTES + 1],
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        let long = JSONL.replace("row-1", &"x".repeat(MAX_BILLING_ROW_BYTES + 1));
        assert!(parse_canonical_jsonl(long.as_bytes(), REGISTRY.as_bytes(), &registry()).is_err());
    }

    #[test]
    fn strict_mapping_and_rfc4180_csv_reject_duplicates_missing_formulas_and_bounds() {
        assert!(parse_mapped_csv(
            CSV.as_bytes(),
            format!("{MAPPING}extra: true\n").as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_mapped_csv(
            CSV.as_bytes(),
            b"version: 2\n",
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_mapped_csv(
            CSV.replace("rid,start", "rid,rid").as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_mapped_csv(
            CSV.replace(",1.250000,", ",=1+1,").as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_mapped_csv(
            CSV.replace(",x\r\n", "\"unterminated\r\n").as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_mapped_csv(
            &vec![b'x'; MAX_BILLING_INPUT_BYTES + 1],
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
        assert!(parse_mapped_csv(
            CSV.as_bytes(),
            &vec![b'x'; MAX_MAPPING_BYTES + 1],
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
    }

    #[test]
    fn strict_rfc4180_lexing_rejects_quotes_line_endings_and_large_raw_records() {
        for malformed in [
            CSV.replace("row-1", "row\"-1"),
            CSV.replace("row-1", "row-1\""),
            CSV.replace("\r\n", "\n"),
            CSV.replace("\r\n", "\r"),
        ] {
            assert!(
                parse_mapped_csv(
                    malformed.as_bytes(),
                    MAPPING.as_bytes(),
                    REGISTRY.as_bytes(),
                    &registry()
                )
                .is_err(),
                "accepted malformed CSV: {malformed:?}"
            );
        }

        let extra_headers = (0..10).map(|i| format!("extra{i}")).collect::<Vec<_>>();
        let fields = (0..10)
            .map(|_| format!("\"{}\"", "x\r\n".repeat(700)))
            .collect::<Vec<_>>();
        let oversized = format!(
            "rid,start,end,supply,currency,basis,charge,requests,inputs,outputs,{}\r\nrow-1,0,1,public/east,USD,inference-usage-net,1.250000,,2,3,{}\r\n",
            extra_headers.join(","),
            fields.join(",")
        );
        assert!(oversized.len() > MAX_BILLING_ROW_BYTES);
        assert!(parse_mapped_csv(
            oversized.as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_err());
    }

    #[test]
    fn strict_rfc4180_accepts_escaped_quotes_quoted_newlines_and_crlf() {
        let valid = CSV.replace(",x\r\n", ",\"escaped \"\"quote\"\" and\r\nnewline\"\r\n");
        assert!(parse_mapped_csv(
            valid.as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_ok());
    }

    #[test]
    fn strict_rfc4180_rejects_blank_records_and_unquoted_controls() {
        for invalid in [
            format!("\r\n{CSV}"),
            CSV.replacen("\r\n", "\r\n\r\n", 1),
            format!("{CSV}\r\n"),
            CSV.replace("row-1", "row\t-1"),
            CSV.replace("row-1", "row\0-1"),
        ] {
            assert!(parse_mapped_csv(
                invalid.as_bytes(),
                MAPPING.as_bytes(),
                REGISTRY.as_bytes(),
                &registry()
            )
            .is_err());
        }
    }

    #[test]
    fn strict_rfc4180_rejects_controls_inside_quoted_ignored_columns() {
        for control in ["\0", "\t", "\u{0001}", "\u{007f}"] {
            let invalid = CSV.replace(",x\r\n", &format!(",\"safe{control}unsafe\"\r\n"));
            assert!(parse_mapped_csv(
                invalid.as_bytes(),
                MAPPING.as_bytes(),
                REGISTRY.as_bytes(),
                &registry()
            )
            .is_err());
        }
        let valid = CSV.replace(",x\r\n", ",\"café, \"\"quoted\"\"\"\r\n");
        assert!(parse_mapped_csv(
            valid.as_bytes(),
            MAPPING.as_bytes(),
            REGISTRY.as_bytes(),
            &registry()
        )
        .is_ok());
    }

    #[test]
    fn registry_source_is_bounded_before_parse() {
        assert!(matches!(
            parse_canonical_jsonl(
                JSONL.as_bytes(),
                &vec![b' '; MAX_REGISTRY_BYTES + 1],
                &registry()
            ),
            Err(BillingParseError::RegistryLimit)
        ));
    }
}
