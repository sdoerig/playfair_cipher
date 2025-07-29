//! This is the implentation of the FourSquare cipher as described
//! <https://en.wikipedia.org/wiki/Four-square_cipher>
//!

use crate::{
    cryptable::{Cipher, Crypt},
    errors::CharNotInKeyError,
    playfair::EMPTY_SQ_POS,
    structs::{CryptModus, CryptResult, Payload},
};

use super::playfair::PlayFairKey;

/// Four square cipher works as its name suggests with those 4 squares.
/// E.g. having this key matrix
///
/// abcde EXAMP
/// fghik LBCDF
/// lmnop GHIKN
/// qrstu OQRST
/// vwxyz UVWYZ
///
/// KEYWO abcde
/// RDABC fghik
/// FGHIL lmnop
/// MNPQS qrstu
/// TUVXZ vwxyz
///
///
pub struct FourSquare {
    // Within the struct, top left and bottom right square are represented by the standard
    // as they are the same
    top_right: PlayFairKey,
    bottom_left: PlayFairKey,
    standard_key: PlayFairKey,
}

impl FourSquare {
    /// Constructs a new Four square cipher based on a
    /// 5 to 5 square. J is replaced by I, no digits. Passkeys can only
    /// contain A-I and K-Z. They should be choosen differntly.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::four_square::FourSquare as FourSquare;
    ///
    /// let pfc = FourSquare::new_5_to_5("Secret", "JamesBond");
    /// ```
    pub fn new_5_to_5(key0: &str, key1: &str) -> Self {
        FourSquare {
            top_right: PlayFairKey::new_5_to_5(key0),
            bottom_left: PlayFairKey::new_5_to_5(key1),
            standard_key: PlayFairKey::new_5_to_5(""),
        }
    }

    /// Constructs a new Four square cipher based on a
    /// 6 to 6 square. A-Z and 0-9 are encryptable. Passkeys can only
    /// contain A-Z and 0-9. They should be choosen differntly.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::four_square::FourSquare as FourSquare;
    ///
    /// let pfc = FourSquare::new_6_to_6("Secret123", "456JamesBond");
    ///
    pub fn new_6_to_6(key0: &str, key1: &str) -> Self {
        FourSquare {
            top_right: PlayFairKey::new_6_to_6(key0),
            bottom_left: PlayFairKey::new_6_to_6(key1),
            standard_key: PlayFairKey::new_6_to_6(""),
        }
    }
}

impl Crypt for FourSquare {
    fn crypt(
        &self,
        a: &str,
        b: &str,
        modus: &crate::structs::CryptModus,
    ) -> Result<crate::structs::CryptResult, crate::errors::CharNotInKeyError> {
        // Working with this key matrix:
        // abcde EXAMP
        // fghik LBCDF
        // lmnop GHIKN
        // qrstu OQRST
        // vwxyz UVWYZ
        //
        // KEYWO abcde
        // RDABC fghik
        // FGHIL lmnop
        // MNPQS qrstu
        // TUVXZ vwxyz
        //
        // encrypting DIAZ -> IOEX
        // a.D -> row 1, col 3  decrypt a.I.row 1, b.O.col 3 -> 1 * 5 + 3 =  8 (I)
        // b.I -> row 2, col 3  decrypt b.O.row 2, a.J.col 3 -> 2 * 5 + 3 = 13 (O)
        //
        let (top_right_hash_map, bottom_left_hash_map, top_left_key, bottom_right_key) = match modus
        {
            CryptModus::Encrypt => (
                &self.standard_key.key_map,
                &self.standard_key.key_map,
                &self.top_right.key,
                &self.bottom_left.key,
            ),
            CryptModus::Decrypt => (
                &self.top_right.key_map,
                &self.bottom_left.key_map,
                &self.standard_key.key,
                &self.standard_key.key,
            ),
        };

        let a_sq_pos = match top_right_hash_map.get(a) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        let b_sq_pos = match bottom_left_hash_map.get(b) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        if a_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                a, &top_right_hash_map
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                b, &self.bottom_left.key
            )));
        }
        let a_crypted_idx = a_sq_pos.row * self.standard_key.square + b_sq_pos.column;
        let b_crypted_idx = b_sq_pos.row * self.standard_key.square + a_sq_pos.column;
        let a_crypted = match top_left_key.get(a_crypted_idx) {
            Some(s) => s,
            None => &String::from("*"),
        };
        let b_crypted = match bottom_right_key.get(b_crypted_idx) {
            Some(s) => s,
            None => &String::from("*"),
        };
        Ok(CryptResult {
            a: a_crypted.clone(),
            b: b_crypted.clone(),
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
        self.bottom_left.payload(payload)
    }
}

impl Cipher for FourSquare {
    /// Encrypts a string. Note as the Four Square cipher is only able to encrypt the
    /// characters A-I and L-Z any spaces and J are cleared off.
    ///
    /// # Example using 5 to 5
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Four-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let fsq = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    /// match fsq.encrypt("joe") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "DIAZ");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    ///
    /// # Example using 6 to 6
    ///
    /// ```
    /// use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let fsq = FourSquare::new_6_to_6("EXAMPLE", "KEYWORD");
    /// match fsq.encrypt("Ben Wade takes the 3:10 train to Yuma.") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "PEOQMKXUPDEUSAL201WIADJQI0RJLP");
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
    /// As described at <https://en.wikipedia.org/wiki/Four-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let fsq = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    /// match fsq.decrypt("DIAZ") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "IOEX");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    /// Example using 6 to 6
    ///
    /// ```
    /// use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let fsq = FourSquare::new_6_to_6("EXAMPLE", "KEYWORD");
    /// match fsq.decrypt("PEOQMKXUPDEUSAL201WIADJQI0RJLP") {
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
    // abcde EXAMP
    // fghik LBCDF
    // lmnop GHIKN
    // qrstu OQRST
    // vwxyz UVWYZ
    //
    // KEYWO abcde
    // RDABC fghik
    // FGHIL lmnop
    // MNPQS qrstu
    // TUVXZ vwxyz
    //
    // encrypting JOE -> DIAZ
    //

    #[test]
    fn test_four_square_creation_key() {
        let four_square = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
        assert!(
            four_square.standard_key.key
                == vec![
                    "A", "B", "C", "D", "E", "F", "G", "H", "I", "K", "L", "M", "N", "O", "P", "Q",
                    "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
                ]
        );

        assert!(
            four_square.top_right.key
                == vec![
                    "E", "X", "A", "M", "P", "L", "B", "C", "D", "F", "G", "H", "I", "K", "N", "O",
                    "Q", "R", "S", "T", "U", "V", "W", "Y", "Z"
                ]
        );
        assert!(
            four_square.bottom_left.key
                == vec![
                    "K", "E", "Y", "W", "O", "R", "D", "A", "B", "C", "F", "G", "H", "I", "L", "M",
                    "N", "P", "Q", "S", "T", "U", "V", "X", "Z"
                ]
        );
    }

    #[test]
    fn test_four_square_encrypt() {
        let four_square = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
        match four_square.encrypt("The quick red fox jumps over the lazy brown dog.") {
            Ok(s) => assert!(s == "RBESSCPATEEBIXFQNGSHZKSNFYGKYZXNHXKYHB"),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }

    #[test]
    fn test_four_square_decrypt() {
        let four_square = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
        match four_square.decrypt("RBESSCPATEEBIXFQNGSHZKSNFYGKYZXNHXKYHB") {
            Ok(s) => assert!(s == "THEQUICKREDFOXIUMPSOVERTHELAZYBROWNDOG"),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }
    #[test]
    fn test_four_square_encrypt_6_to_6() {
        let four_square = FourSquare::new_6_to_6("Shelley3746", "Mary234");
        match four_square.encrypt("The Modern Prometheus 1818") {
            Ok(s) => assert!(s == "NBSKIR3KIHGLJMNBESPU5Z9S", "{}", format!("got {s}")),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }

    #[test]
    fn test_four_square_decrypt_6_to_6() {
        let four_square = FourSquare::new_6_to_6("Shelley3746", "Mary234");
        match four_square.decrypt("NBSKIR3KIHGLJMNBESPU5Z9S") {
            Ok(s) => assert!(s == "THEMODERNPROMETHEUS1818X", "{}", format!("got {s}")),
            Err(e) => panic!("CharNotInKeyError {e}"),
        }
    }
}
