use std::error::Error;

use std::fmt;

/// Error indicating a character in the given string could not be looked up in the
/// PlayFairKey. If this occours any operation is stopped.
///
#[derive(Debug, Clone)]
pub struct CharNotInKeyError {
    pub(crate) error: String,
}

impl fmt::Display for CharNotInKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for CharNotInKeyError {}

impl CharNotInKeyError {
    pub(crate) fn new(error: String) -> Self {
        CharNotInKeyError { error }
    }
}
