//! A password that cannot leak by accident: no `Display`, a redacted `Debug`,
//! no `Clone`, and zeroed on drop.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Name of the environment variable `pathwarden collect` reads the password from.
pub const PASSWORD_ENV: &str = pathwarden_core::keystore::COLLECT_PASSWORD_ENV;

/// A secret string (a password). Its memory is zeroed when it is dropped.
/// Read it only with [`Secret::expose`], at the point of use.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The secret value. Do not format, log or store it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A second copy, also zeroed on drop: for a request that differs only
    /// in where it writes (see `CollectRequest::writing_to`). Not `Clone`,
    /// so copies stay deliberate.
    pub(crate) fn duplicate(&self) -> Self {
        Self::new(self.expose().to_string())
    }

    /// The password in `PATHWARDEN_COLLECT_PASSWORD`, as `main` took it
    /// from the environment at start-up
    /// ([`pathwarden_core::keystore::take_env`]), so no program Pathwarden
    /// starts inherits it. `None` when unset, empty or not valid Unicode.
    pub fn from_env() -> Option<Self> {
        let value = pathwarden_core::keystore::secret_env(PASSWORD_ENV).ok()??;
        Some(Self::new(value.as_str()))
    }

    /// Prompts on the terminal without echo.
    pub fn prompt(prompt: &str) -> std::io::Result<Self> {
        let mut value = rpassword::prompt_password(prompt)?;
        let secret = Self::new(value.clone());
        value.zeroize();
        Ok(secret)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

/// Reads a password straight into a `Secret` (e.g. from a JSON request
/// body). There is deliberately no `Serialize`.
impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret::from)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("Hunter2!correct-horse");
        let shown = format!("{s:?} {s:#?}");
        assert!(!shown.contains("Hunter2"), "{shown}");
        assert!(shown.contains("redacted"));
        assert_eq!(s.expose(), "Hunter2!correct-horse");
    }

    #[test]
    fn deserializes_from_json() {
        #[derive(serde::Deserialize, Debug)]
        struct Form {
            password: Secret,
        }
        let f: Form = serde_json::from_str(r#"{"password":"Pa\"ss-77"}"#).unwrap();
        assert_eq!(f.password.expose(), "Pa\"ss-77");
        assert!(!format!("{f:?}").contains("ss-77"));
    }

    #[test]
    fn redacted_inside_derived_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            user: String,
            password: Secret,
        }
        let h = Holder {
            user: "svc".into(),
            password: Secret::new("TopSecret123"),
        };
        let shown = format!("{h:?}");
        assert!(!shown.contains("TopSecret123"), "{shown}");
        assert!(shown.contains("svc"));
    }
}
