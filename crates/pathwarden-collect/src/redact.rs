//! Keeps secrets out of collector log lines before they reach the Collect
//! page, `/api/jobs`, the terminal or an error message: the rule is
//! [`pathwarden_core::redact::collector_line`], shared with the logs.

#[cfg(test)]
use std::borrow::Cow;

#[cfg(test)]
pub(crate) use pathwarden_core::redact::HIDDEN;

/// `line`, or a safe replacement when it may carry a password.
pub(crate) use pathwarden_core::redact::collector_line as log_line;

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
