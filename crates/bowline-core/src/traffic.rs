use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolKind {
    #[default]
    ChatCompletions,
    Responses,
    Embeddings,
    Unsupported,
}

impl ProtocolKind {
    pub fn is_supported(self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationSource {
    #[default]
    Inline,
    Passive,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageStatus {
    #[default]
    Supported,
    IncompleteObservation,
    UnsupportedProtocol,
    UnsupportedShape,
}
