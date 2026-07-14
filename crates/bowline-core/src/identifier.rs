pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// The content-free identifier grammar shared by configuration and durable authority evidence.
pub fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}
