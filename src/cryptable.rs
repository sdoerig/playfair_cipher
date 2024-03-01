//! Traits indicating the cryptablilty of a modul  

use crate::{
    errors::CharNotInKeyError,
    structs::{CryptModus, CryptResult},
};

pub(crate) trait Crypt {
    fn crypt_payload(&self, payload: &str, modus: &CryptModus)
        -> Result<String, CharNotInKeyError>;
    fn crypt(&self, a: char, b: char, modus: &CryptModus)
        -> Result<CryptResult, CharNotInKeyError>;
}

pub trait Cypher {
    fn encrypt(&self, payload: &str) -> Result<String, CharNotInKeyError>;
    fn decrypt(&self, payload: &str) -> Result<String, CharNotInKeyError>;
}
