use axum::http::HeaderMap;
use bowline_core::{
    enforcement::{route_workload_digest, AuthorityProtocol, WorkloadSelector},
    policy::{PolicyBundle, WorkloadIdentity},
    supply::TaskClass,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorityHeader<T> {
    Absent,
    Valid(T),
    Invalid,
}

pub fn extract_identity(headers: &HeaderMap, path: &str) -> WorkloadIdentity {
    WorkloadIdentity {
        api_key_digest: bearer_digest(headers),
        route: path.to_string(),
        app: header_value(headers, "x-bowline-app"),
        tags: Vec::new(),
    }
}

pub fn declared_task_class(headers: &HeaderMap) -> Option<TaskClass> {
    match resolve_task_header(headers) {
        AuthorityHeader::Valid(task) => Some(task),
        AuthorityHeader::Absent | AuthorityHeader::Invalid => None,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedRequestContext {
    pub(crate) identity: WorkloadIdentity,
    pub(crate) identity_trusted: bool,
    pub(crate) authority_metadata_valid: bool,
    pub(crate) app: Option<String>,
    pub(crate) resolved_tags: Vec<String>,
    pub(crate) task_class: TaskClass,
    pub(crate) workload_identity_digest: Option<String>,
}

pub(crate) fn resolve_request_context(
    policy: &PolicyBundle,
    headers: &HeaderMap,
    trusted_peer: bool,
    path: &str,
    protocol: AuthorityProtocol,
) -> ResolvedRequestContext {
    let untrusted_assertion = !trusted_peer
        && (headers.contains_key("x-bowline-app") || headers.contains_key("x-bowline-task-class"));
    let mut trusted_headers = headers.clone();
    if !trusted_peer {
        trusted_headers.remove("x-bowline-app");
        trusted_headers.remove("x-bowline-task-class");
    }
    let app_header = resolve_app_header(&trusted_headers);
    let task_header = resolve_task_header(&trusted_headers);
    let authority_metadata_valid = !untrusted_assertion
        && app_header != AuthorityHeader::Invalid
        && task_header != AuthorityHeader::Invalid;
    let mut identity = extract_identity(&trusted_headers, path);
    let app = match app_header {
        AuthorityHeader::Valid(app) => Some(app),
        AuthorityHeader::Absent | AuthorityHeader::Invalid => None,
    };
    identity.app = app.clone();
    let resolved_tags = policy.resolve_tags(&identity);
    identity.tags = resolved_tags.clone();
    let task_class = match task_header {
        AuthorityHeader::Valid(task) => task,
        AuthorityHeader::Absent | AuthorityHeader::Invalid => policy.task_class_for(&identity),
    };
    let workload_identity_digest = app.as_ref().and_then(|app| {
        route_workload_digest(
            protocol,
            &WorkloadSelector {
                app: app.clone(),
                resolved_tags: resolved_tags.clone(),
            },
        )
        .ok()
    });
    ResolvedRequestContext {
        identity,
        identity_trusted: trusted_peer && app.is_some(),
        authority_metadata_valid,
        app,
        resolved_tags,
        task_class,
        workload_identity_digest,
    }
}

fn bearer_digest(headers: &HeaderMap) -> Option<String> {
    let authorization = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = authorization.split_once(' ')?;

    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }

    let digest = Sha256::digest(token.as_bytes());
    Some(format!("sha256:{digest:x}"))
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    match resolve_identifier_header(headers, name) {
        AuthorityHeader::Valid(value) => Some(value),
        AuthorityHeader::Absent | AuthorityHeader::Invalid => None,
    }
}

fn resolve_app_header(headers: &HeaderMap) -> AuthorityHeader<String> {
    resolve_identifier_header(headers, "x-bowline-app")
}

fn resolve_identifier_header(headers: &HeaderMap, name: &str) -> AuthorityHeader<String> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return AuthorityHeader::Absent;
    };
    if values.next().is_some() {
        return AuthorityHeader::Invalid;
    }
    let Ok(value) = value.to_str() else {
        return AuthorityHeader::Invalid;
    };
    if value == "untrusted"
        || value.contains(',')
        || !bowline_core::identifier::is_bounded_identifier(value)
    {
        AuthorityHeader::Invalid
    } else {
        AuthorityHeader::Valid(value.to_owned())
    }
}

fn resolve_task_header(headers: &HeaderMap) -> AuthorityHeader<TaskClass> {
    match resolve_identifier_header(headers, "x-bowline-task-class") {
        AuthorityHeader::Absent => AuthorityHeader::Absent,
        AuthorityHeader::Invalid => AuthorityHeader::Invalid,
        AuthorityHeader::Valid(value) => match value.as_str() {
            "mechanical" => AuthorityHeader::Valid(TaskClass::Mechanical),
            "heavy-lifting" => AuthorityHeader::Valid(TaskClass::HeavyLifting),
            "taste-sensitive" => AuthorityHeader::Valid(TaskClass::TasteSensitive),
            "judgment" => AuthorityHeader::Valid(TaskClass::Judgment),
            "unclassified" => AuthorityHeader::Valid(TaskClass::Unclassified),
            _ => AuthorityHeader::Invalid,
        },
    }
}
