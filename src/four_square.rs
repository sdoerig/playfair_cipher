//! This is the implentation of the FourSquare cipher as described
//! <https://en.wikipedia.org/wiki/Four-square_cipher>
//!

use crate::{
    errors::CharNotInKeyError,
    playfair::{EMPTY_SQ_POS, ROW_LENGTH},
    structs::{CryptModus, CryptResult, Payload},
};

use super::playfair::{Crypt, Cypher, PlayFairKey};

pub struct FourSquare {
    top_left: PlayFairKey,
    top_right: PlayFairKey,
    bottom_left: PlayFairKey,
    bottom_right: PlayFairKey,
}

impl FourSquare {
    pub fn new(key0: &str, key1: &str) -> Self {
        FourSquare {
            top_left: PlayFairKey::new(""),
            top_right: PlayFairKey::new(key0),
            bottom_left: PlayFairKey::new(key1),
            bottom_right: PlayFairKey::new(""),
        }
    }

    fn encrypt_digram(&self, a: char, b: char) -> Result<CryptResult, CharNotInKeyError> {
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
        // a.I -> row 1, col 3  encrypt a.I.row 1, b.O.col 3 -> 1 * 5 + 3 =  8 (D)
        // b.O -> row 2, col 3  encrypt b.O.row 2, a.J.col 3 -> 2 * 5 + 3 = 13 (I)
        //
        let a_sq_pos = match self.top_left.key_map.get(&a) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        let b_sq_pos = match self.bottom_right.key_map.get(&b) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        if a_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                a, &self.top_left.key
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                b, &self.bottom_right.key
            )));
        }
        let a_crypted_idx: u8 = a_sq_pos.row * ROW_LENGTH + b_sq_pos.column;
        let b_crypted_idx: u8 = b_sq_pos.row * ROW_LENGTH + a_sq_pos.column;
        let a_crypted = match self.top_right.key.get(a_crypted_idx as usize) {
            Some(s) => *s,
            None => '*',
        };
        let b_crypted = match self.bottom_left.key.get(b_crypted_idx as usize) {
            Some(s) => *s,
            None => '*',
        };
        Ok(CryptResult {
            a: a_crypted,
            b: b_crypted,
        })
    }

    fn decrypt_digram(&self, a: char, b: char) -> Result<CryptResult, CharNotInKeyError> {
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
        let a_sq_pos = match self.top_right.key_map.get(&a) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        let b_sq_pos = match self.bottom_left.key_map.get(&b) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        if a_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                a, &self.top_right.key
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                b, &self.bottom_left.key
            )));
        }
        let a_crypted_idx: u8 = a_sq_pos.row * ROW_LENGTH + b_sq_pos.column;
        let b_crypted_idx: u8 = b_sq_pos.row * ROW_LENGTH + a_sq_pos.column;
        let a_crypted = match self.top_left.key.get(a_crypted_idx as usize) {
            Some(s) => *s,
            None => '*',
        };
        let b_crypted = match self.bottom_right.key.get(b_crypted_idx as usize) {
            Some(s) => *s,
            None => '*',
        };
        Ok(CryptResult {
            a: a_crypted,
            b: b_crypted,
        })
    }
}

impl Crypt for FourSquare {
    fn crypt(
        &self,
        a: char,
        b: char,
        modus: &crate::structs::CryptModus,
    ) -> Result<crate::structs::CryptResult, crate::errors::CharNotInKeyError> {
        match modus {
            CryptModus::Encrypt => self.encrypt_digram(a, b),

            CryptModus::Decrypt => self.decrypt_digram(a, b),
        }
    }

    fn crypt_payload(
        &self,
        payload: &str,
        modus: &crate::structs::CryptModus,
    ) -> Result<String, crate::errors::CharNotInKeyError> {
        //let char_tuples = into_pairs(payload);
        let mut payload_encrypted = String::new();
        let mut payload_iter = Payload::new(payload);
        loop {
            let digram = payload_iter.next();
            let [a, b] = match digram {
                Some(d) => d,
                None => break,
            };
            match self.crypt(a, b, modus) {
                Ok(digram_crypt) => {
                    payload_encrypted += &String::from(digram_crypt.a);
                    payload_encrypted += &String::from(digram_crypt.b);
                }
                Err(e) => return Err(e),
            };
        }
        Ok(payload_encrypted)
    }
}

impl Cypher for FourSquare {
    /// Encrypts a string. Note as the Four Square cipher is only able to encrypt the
    /// characters A-I and L-Z any spaces and J are cleared off.
    ///
    /// # Example
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Four-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
    /// use crate::playfair_cipher::playfair::Cypher;
    ///
    /// let fsq = FourSquare::new("EXAMPLE", "KEYWORD");
    /// match fsq.encrypt("joe") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "DIAZ");
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
    /// As described at <https://en.wikipedia.org/wiki/Four-square_cipher>
    ///
    /// ```
    /// use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
    /// use crate::playfair_cipher::playfair::Cypher;
    ///
    /// let fsq = FourSquare::new("EXAMPLE", "KEYWORD");
    /// match fsq.decrypt("DIAZ") {
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
        let four_square = FourSquare::new("EXAMPLE", "KEYWORD");
        assert!(
            four_square.top_left.key
                == vec![
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
                    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
                ]
        );
        assert!(
            four_square.bottom_right.key
                == vec![
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
                    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
                ]
        );
        assert!(
            four_square.top_right.key
                == vec![
                    'E', 'X', 'A', 'M', 'P', 'L', 'B', 'C', 'D', 'F', 'G', 'H', 'I', 'K', 'N', 'O',
                    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Y', 'Z'
                ]
        );
        assert!(
            four_square.bottom_left.key
                == vec![
                    'K', 'E', 'Y', 'W', 'O', 'R', 'D', 'A', 'B', 'C', 'F', 'G', 'H', 'I', 'L', 'M',
                    'N', 'P', 'Q', 'S', 'T', 'U', 'V', 'X', 'Z'
                ]
        );
    }

    #[test]
    fn test_four_square_encrypt() {
        let four_square = FourSquare::new("EXAMPLE", "KEYWORD");
        match four_square.encrypt("The quick red fox jumps over the lazy brown dog.") {
            Ok(s) => assert!(s == "RBESSCPATEEBIXFQNGSHZKSNFYGKYZXNHXKYHB"),
            Err(_) => todo!(),
        }
    }

    #[test]
    fn test_four_square_decrypt() {
        let four_square = FourSquare::new("EXAMPLE", "KEYWORD");
        match four_square.decrypt("RBESSCPATEEBIXFQNGSHZKSNFYGKYZXNHXKYHB") {
            Ok(s) => assert!(s == "THEQUICKREDFOXIUMPSOVERTHELAZYBROWNDOG"),
            Err(_) => todo!(),
        }
    }
}