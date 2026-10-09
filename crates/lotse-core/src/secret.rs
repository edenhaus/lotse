//! [`Secret`]: a value whose `Debug` and `Display` print `****`, so camera
//! credentials cannot reach a log line, an API result or an error message by
//! accident.

use std::fmt;

/// What a redacted secret prints as.
pub const REDACTED: &str = "****";

/// A value that never prints. Read it with [`Secret::expose_secret`], and only
/// where the value leaves the process toward its own source (an RTSP
/// `Authorization` header, a TURN allocation).
///
/// Equality and hashing see the real value, because the canonical source key
/// includes the credentials.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The real value. The name is deliberately loud, so it stands out in review.
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Unwraps the real value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let secret = Secret::new(String::from("hunter2"));
        assert_eq!(format!("{secret:?}"), "Secret(****)");
        assert_eq!(format!("{secret}"), "****");
        assert_eq!(format!("{:?}", Some(&secret)), "Some(Secret(****))");
    }

    #[test]
    fn expose_and_into_inner_return_the_value() {
        let secret: Secret<&str> = "hunter2".into();
        assert_eq!(*secret.expose_secret(), "hunter2");
        assert_eq!(secret.into_inner(), "hunter2");
    }

    #[test]
    fn equality_sees_the_real_value() {
        assert_eq!(Secret::new(1), Secret::new(1));
        assert_ne!(Secret::new(1), Secret::new(2));
        assert_eq!(Secret::<u8>::default(), Secret::new(0));
    }
}
