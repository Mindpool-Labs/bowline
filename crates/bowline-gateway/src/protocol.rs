use bowline_core::traffic::ProtocolKind;

pub const INFERENCE_PROTOCOL_CATALOG: [(&str, ProtocolKind); 12] = [
    ("/v1/chat/completions", ProtocolKind::ChatCompletions),
    ("/v1/responses", ProtocolKind::Responses),
    ("/v1/embeddings", ProtocolKind::Embeddings),
    ("/v1/completions", ProtocolKind::Unsupported),
    ("/v1/audio/transcriptions", ProtocolKind::Unsupported),
    ("/v1/audio/translations", ProtocolKind::Unsupported),
    ("/v1/audio/speech", ProtocolKind::Unsupported),
    ("/v1/images/generations", ProtocolKind::Unsupported),
    ("/v1/images/edits", ProtocolKind::Unsupported),
    ("/v1/images/variations", ProtocolKind::Unsupported),
    ("/v1/moderations", ProtocolKind::Unsupported),
    ("/v1/rerank", ProtocolKind::Unsupported),
];

pub fn classify_inference_protocol(method: &str, path: &str) -> Option<ProtocolKind> {
    if method != "POST" {
        return None;
    }
    INFERENCE_PROTOCOL_CATALOG
        .iter()
        .find_map(|(catalog_path, protocol)| (*catalog_path == path).then_some(*protocol))
}
