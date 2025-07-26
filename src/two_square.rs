//! This is the implentation of the TwoSquare cipher as described
//! <https://en.wikipedia.org/wiki/Two-square_cipher>
//!

use crate::{
    cryptable::{Cipher, Crypt},
    errors::CharNotInKeyError,
    playfair::EMPTY_SQ_POS,
    structs::{CryptModus, CryptResult, Payload},
};

use super::playfair::PlayFairKey;

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
    /// Constructs a new Two square cipher based on a
    /// 5 to 5 square. J is replaced by I, no digits. Passkeys can only
    /// contain A-I and K-Z. They should be choosen differntly.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::two_square::TwoSquare as TwoSquare;
    ///
    /// let pfc = TwoSquare::new_5_to_5("Secret", "JamesBond");
    /// ```
    pub fn new_5_to_5(key0: &str, key1: &str) -> Self {
        TwoSquare {
            top: PlayFairKey::new_5_to_5(key0),
            bottom: PlayFairKey::new_5_to_5(key1),
        }
    }

    /// Constructs a new Two square cipher based on a
    /// 6 to 6 square. A-Z and 0-9 are encryptable. Passkeys can only
    /// contain A-Z and 0-9. They should be choosen differntly.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::two_square::TwoSquare as TwoSquare;
    ///
    /// let pfc = TwoSquare::new_6_to_6("Secret123", "456JamesBond");
    /// ```
    pub fn new_6_to_6(key0: &str, key1: &str) -> Self {
        TwoSquare {
            top: PlayFairKey::new_6_to_6(key0),
            bottom: PlayFairKey::new_6_to_6(key1),
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
            a_sq_pos.row * self.top.square + b_sq_pos.column,
            b_sq_pos.row * self.top.square + a_sq_pos.column,
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
        let mut payload_iter = Payload::new(self.playload(payload));

        payload_iter.crypt_payload(self, modus)
    }

    fn playload(&self, payload: &str) -> String {
        self.top.payload(payload)
    }
}

impl Cipher for TwoSquare {
    /// Encrypts a string. Note as the Two Square cipher is only able to encrypt the
    /// characters A-I and L-Z any spaces and J are cleared off.
    ///
    /// # Example 5 to 5
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Two-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;;
    ///
    /// let tsq = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    /// match tsq.encrypt("joe") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "NYMT");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    /// # Example 6 to 6
    ///
    /// ```
    /// use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;;
    ///
    /// let tsq = TwoSquare::new_6_to_6("EXAMPLE", "KEYWORD");
    /// match tsq.encrypt("Ben Wade takes the 3:10 train to Yuma.") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "CKNWEBMPEYAPRJLX01WYXJNTKOVLE0");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    fn encrypt(&self, payload: &str) -> Result<String, crate::errors::CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Encrypt)
    }

    /// Decrypts a string.
    ///
    /// # Example 5 to 5
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Two-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let tsq = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    /// match tsq.decrypt("NYMT") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "IOEX");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    /// # Example 6 to 6
    ///
    /// ```
    /// use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;;
    ///
    /// let tsq = TwoSquare::new_6_to_6("EXAMPLE", "KEYWORD");
    /// match tsq.decrypt("CKNWEBMPEYAPRJLX01WYXJNTKOVLE0") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "BENWADETAKESTHE310TRAINTOYUMAX");
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
        let two_square = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");

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
        let two_square = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
        match two_square.encrypt("HELPMEOBIWANKENOBI") {
            Ok(s) => assert!(&s == "HECMXWSRKYXPHWNODG", "{}", s),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }

    #[test]
    fn test_two_square_decrypt() {
        let two_square = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
        match two_square.decrypt("HECMXWSRKYXPHWNODG") {
            Ok(s) => assert!(s == "HELPMEOBIWANKENOBI"),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }

    #[test]
    fn test_two_square_encrypt_second() {
        let two_square = TwoSquare::new_5_to_5("UEMFUI", "NIHKGDTMSXSEMLGIFW");
        match two_square.encrypt("HELPMEOBIWANKENOBI") {
            Ok(s) => assert!(&s == "HENOUFHQFAANHLLPBI", "{}", s),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }

    #[test]
    fn test_two_square_decrypt_second() {
        let two_square = TwoSquare::new_5_to_5("UEMFUI", "NIHKGDTMSXSEMLGIFW");
        match two_square.decrypt("HENOUFHQFAANHLLPBI") {
            Ok(s) => assert!(&s == "HELPMEOBIWANKENOBI", "{}", s),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }
    #[test]
    fn test_two_square_6_to_6_encrypt() {
        let two_square = TwoSquare::new_6_to_6("example1234", "SEcret85736");
        match two_square.encrypt("Ben Wade takes the 3:10 train to Yuma.") {
            Ok(s) => assert!(&s == "2TQUEGPSEMESWDA52ZWSPGRESVVLPV", "{}", s),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }

    #[test]
    fn test_two_square_6_to_6_decrypt() {
        let two_square = TwoSquare::new_6_to_6("example1234", "SEcret85736");
        match two_square.decrypt("2TQUEGPSEMESWDA52ZWSPGRESVVLPV") {
            Ok(s) => assert!(&s == "BENWADETAKESTHE310TRAINTOYUMAX", "{}", s),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }
}
