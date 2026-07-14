use sha2::{Digest, Sha256};

pub(crate) const CANDIDATE_CONFIG_DOMAIN: &[u8] = b"bowline-canary-candidate-config-v1";
pub(crate) const JUDGE_MODEL_DOMAIN: &[u8] = b"bowline-canary-judge-model-v1";
pub(crate) const JUDGE_RUBRIC_DOMAIN: &[u8] = b"bowline-canary-judge-rubric-v1";
pub(crate) const JUDGE_TEMPLATE_DOMAIN: &[u8] = b"bowline-canary-judge-template-v1";
pub(crate) const JUDGE_CONFIG_DOMAIN: &[u8] = b"bowline-canary-judge-config-v1";
pub(crate) const JUDGE_ENDPOINT_DOMAIN: &[u8] = b"bowline-canary-judge-endpoint-v1";
pub(crate) const JUDGE_AUTHORIZATION_REFERENCE_DOMAIN: &[u8] =
    b"bowline-canary-judge-authorization-reference-v1";

pub(crate) fn digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    update_field(&mut digest, domain);
    digest.update((fields.len() as u64).to_be_bytes());
    for field in fields {
        update_field(&mut digest, field);
    }
    format!("sha256:{:x}", digest.finalize())
}

fn update_field(digest: &mut Sha256, field: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_digests_are_domain_separated_length_prefixed_and_stable() {
        let candidate = digest(
            CANDIDATE_CONFIG_DOMAIN,
            &[b"ab".as_slice(), b"c".as_slice()],
        );
        let candidate_other_boundary = digest(
            CANDIDATE_CONFIG_DOMAIN,
            &[b"a".as_slice(), b"bc".as_slice()],
        );
        let judge = digest(JUDGE_CONFIG_DOMAIN, &[b"ab".as_slice(), b"c".as_slice()]);
        let template = digest(
            JUDGE_TEMPLATE_DOMAIN,
            &[b"v1".as_slice(), b"instruction".as_slice()],
        );

        assert_eq!(
            candidate,
            "sha256:9e5d2ab7a2ca5e3ef785afeb3cd5e5540426d3259e623fafa78713270a1d6ac6"
        );
        assert_eq!(
            candidate_other_boundary,
            "sha256:3af6d571436a45177c3b4f83dfe8b1d665e2d880f893ea894ec0bac7756382e4"
        );
        assert_eq!(
            judge,
            "sha256:0aa69ec6c5e49e2f532853bbcfdbf1bc31362c5cf8263efa168c3adbb77082dc"
        );
        assert_eq!(
            template,
            "sha256:8e4cb33e353f00c451d01b4e02419783f9e8fe4e76c0d2264959bb4d3fdb4d20"
        );
        assert_ne!(candidate, candidate_other_boundary);
        assert_ne!(candidate, judge);
    }
}
