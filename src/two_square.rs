//! This is the implentation of the TwoSquare cipher as described
//! <https://en.wikipedia.org/wiki/Two-square_cipher>
//!

use crate::{
    errors::CharNotInKeyError,
    playfair::{EMPTY_SQ_POS, ROW_LENGTH},
    structs::{CryptModus, CryptResult, Payload},
};

use super::playfair::{Crypt, Cypher, PlayFairKey};

/// Two square cipher works as its name suggests with those 4 squares.
/// E.g. having this key matrix
///
/// E X A M P
/// L B C D F
/// G H I J K
/// N O R S T
/// U V W Y Z
///  
/// K E Y W O
/// R D A B C
/// F G H I J
/// L M N P S
/// T U V X Z
///
///
pub struct TwoSquare {
    top: PlayFairKey,
    bottom: PlayFairKey,
}

impl TwoSquare {
    pub fn new(key0: &str, key1: &str) -> Self {
        TwoSquare {
            top: PlayFairKey::new(key0),
            bottom: PlayFairKey::new(key1),
        }
    }
}

impl Crypt for TwoSquare {
    fn crypt(
        &self,
        a: char,
        b: char,
        _modus: &crate::structs::CryptModus,
    ) -> Result<crate::structs::CryptResult, crate::errors::CharNotInKeyError> {
        // E X A M P
        // L B C D F
        // G H I K N
        // O Q R S T
        // U V W Y Z
        //
        // K E Y W O
        // R D A B C
        // F G H I L
        // M N P Q S
        // T U V X Z
        //
        // Plaintext:  he lp me ob iw an ke no bi
        // Ciphertext: HE CM XW SR KY XP HW NO DG
        //

        let a_sq_pos = match self.top.key_map.get(&a) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        let b_sq_pos = match self.bottom.key_map.get(&b) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        if a_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                a, &self.top.key
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                b, &self.bottom.key
            )));
        }
        let (a_crypted_idx, b_crypted_idx) = (
            a_sq_pos.row * ROW_LENGTH + b_sq_pos.column,
            b_sq_pos.row * ROW_LENGTH + a_sq_pos.column,
        );
        let a_crypted = match self.top.key.get(a_crypted_idx as usize) {
            Some(s) => *s,
            None => '*',
        };
        let b_crypted = match self.bottom.key.get(b_crypted_idx as usize) {
            Some(s) => *s,
            None => '*',
        };
        Ok(CryptResult {
            a: a_crypted,
            b: b_crypted,
        })
    }

    fn crypt_payload(
        &self,
        payload: &str,
        modus: &crate::structs::CryptModus,
    ) -> Result<String, crate::errors::CharNotInKeyError> {
        let mut payload_iter = Payload::new(payload);

        payload_iter.crypt_payload(self, modus)
    }
}

impl Cypher for TwoSquare {
    /// Encrypts a string. Note as the Two Square cipher is only able to encrypt the
    /// characters A-I and L-Z any spaces and J are cleared off.
    ///
    /// # Example
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Two-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::playfair::Cypher;
    ///
    /// let fsq = TwoSquare::new("EXAMPLE", "KEYWORD");
    /// match fsq.encrypt("joe") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "NYMT");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    fn encrypt(&self, payload: &str) -> Result<String, crate::errors::CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Encrypt)
    }

    /// Decrypts a string.
    ///
    /// # Example
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Two-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::playfair::Cypher;
    ///
    /// let fsq = TwoSquare::new("EXAMPLE", "KEYWORD");
    /// match fsq.decrypt("NYMT") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "IOEX");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    fn decrypt(&self, payload: &str) -> Result<String, crate::errors::CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Decrypt)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // Working with this key matrix:
    // E X A M P
    // L B C D F
    // G H I K N
    // O Q R S T
    // U V W Y Z
    //
    // K E Y W O
    // R D A B C
    // F G H I L
    // M N P Q S
    // T U V X Z
    //
    //

    #[test]
    fn test_two_square_creation_key() {
        let two_square = TwoSquare::new("EXAMPLE", "KEYWORD");

        assert!(
            two_square.top.key
                == vec![
                    'E', 'X', 'A', 'M', 'P', 'L', 'B', 'C', 'D', 'F', 'G', 'H', 'I', 'K', 'N', 'O',
                    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Y', 'Z'
                ]
        );
        assert!(
            two_square.bottom.key
                == vec![
                    'K', 'E', 'Y', 'W', 'O', 'R', 'D', 'A', 'B', 'C', 'F', 'G', 'H', 'I', 'L', 'M',
                    'N', 'P', 'Q', 'S', 'T', 'U', 'V', 'X', 'Z'
                ]
        );
    }

    #[test]
    fn test_two_square_encrypt() {
        let two_square = TwoSquare::new("EXAMPLE", "KEYWORD");
        match two_square.encrypt("helpmeobiwankenobi") {
            Ok(s) => assert!(&s == "HECMXWSRKYXPHWNODG", "{}", s),
            Err(_) => todo!(),
        }
    }

    #[test]
    fn test_two_square_decrypt() {
        let two_square = TwoSquare::new("EXAMPLE", "KEYWORD");
        match two_square.decrypt("HECMXWSRKYXPHWNODG") {
            Ok(s) => assert!(s == "HELPMEOBIWANKENOBI"),
            Err(_) => todo!(),
        }
    }
}
