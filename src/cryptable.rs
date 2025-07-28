//! Traits indicating the cryptablilty of a modul  
//! To be a cipher a module must implement the trait Crypt.
//! Pablic exposed is the modul cipher

use crate::{
    errors::CharNotInKeyError,
    structs::{CryptModus, CryptResult},
};

#[deprecated(
    since = "1.0.2",
    note = "please use `Cipher` instead - I'm sorry for the typo..."
)]
pub use Cipher as Cypher;

/// A cipher must implement this trait to be used.
pub(crate) trait Crypt {
    /// Used to crypt or decrypt a payload. Wrapped by encrypt or decrypt method.
    fn crypt_payload(&self, payload: &str, modus: &CryptModus)
        -> Result<String, CharNotInKeyError>;

    /// This method implements the lookup a all the processing within the modul.
    /// It is called by Payload iterator.
    fn crypt(&self, a: &str, b: &str, modus: &CryptModus)
        -> Result<CryptResult, CharNotInKeyError>;

    /// Ensures only characters contained in the square are present. It
    /// also performs the uppercasing of the payload.
    /// The method should remove all not encryptable characters silent.
    fn playload(&self, payload: &str) -> String;
}

pub trait Cipher {
    fn encrypt(&self, payload: &str) -> Result<String, CharNotInKeyError>;
    fn decrypt(&self, payload: &str) -> Result<String, CharNotInKeyError>;
}
