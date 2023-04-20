//! This is the implentation of the PlayFair cipher as described
//! <https://en.wikipedia.org/wiki/Playfair_cipher>
//!
//! When using the method encrypt the payload is converted to uppercase
//! and any character not within the range A..I and K..Z is ignored.
//! E.g. "I would like 4 tins of jam." becomes "IWOULDLIKETINSOFIAM".
//! So you don't need to clear off not encryptable characters when using
//! this library.
//!
use crate::errors::CharNotInKeyError;

use crate::structs::{CryptModus, CryptResult, Payload, SquarePosition};

use super::ciphers::PlayFairKey;

const EMPTY_SQ_POS: &SquarePosition = &SquarePosition {
    column: 42,
    row: 42,
};

impl PlayFairKey {
    fn crypt(
        &self,
        a: char,
        b: char,
        modus: &CryptModus,
    ) -> Result<CryptResult, CharNotInKeyError> {
        let a_sq_pos = match self.key_map.get(&a) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        let b_sq_pos = match self.key_map.get(&b) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        if a_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                a, &self.key
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - '{}' was not found in key {:?}",
                b, &self.key
            )));
        }
        let mut a_crypted_idx: u8 = 0;
        let mut b_crypted_idx: u8 = 0;
        if a_sq_pos.column != b_sq_pos.column && a_sq_pos.row != b_sq_pos.row {
            // in square mode
            // example 1:
            // _ a _ y _
            // _ _ _ _ _
            // _ z _ b _
            // _ _ _ _ _
            // _ _ _ _ _

            // example 2:
            // _ b _ z _
            // _ _ _ _ _
            // _ y _ a _
            // _ _ _ _ _
            // _ _ _ _ _

            a_crypted_idx = a_sq_pos.row * 5 + b_sq_pos.column;
            b_crypted_idx = b_sq_pos.row * 5 + a_sq_pos.column;
        } else if a_sq_pos.column == b_sq_pos.column {
            // in column mode
            // example 1
            // _ a _ _ _
            // _ y _ _ _
            // _ b _ _ _
            // _ z _ _ _
            // _ _ _ _ _

            // example 2
            // _ y _ _ _
            // _ _ _ _ _
            // _ b _ _ _
            // _ z _ _ _
            // _ a _ _ _

            if modus == &CryptModus::Encrypt {
                if a_sq_pos.row == 4 {
                    // In the last row - so going back to row 0
                    a_crypted_idx = a_sq_pos.column;
                } else {
                    a_crypted_idx = (a_sq_pos.row + 1) * 5 + a_sq_pos.column
                }
                if b_sq_pos.row == 4 {
                    // In the last row - so going back to row 0
                    b_crypted_idx = b_sq_pos.column;
                } else {
                    b_crypted_idx = (b_sq_pos.row + 1) * 5 + b_sq_pos.column
                }
            } else {
                // Decrypting
                if a_sq_pos.row == 0 {
                    a_crypted_idx = 20 + a_sq_pos.column;
                } else {
                    a_crypted_idx = (a_sq_pos.row - 1) * 5 + a_sq_pos.column;
                }
                if b_sq_pos.row == 0 {
                    b_crypted_idx = 20 + b_sq_pos.column;
                } else {
                    b_crypted_idx = (b_sq_pos.row - 1) * 5 + b_sq_pos.column;
                }
            }
        } else if a_sq_pos.row == b_sq_pos.row {
            // in row mode
            // _ _ _ _ _
            // _ _ _ _ _
            // _ a y b z
            // _ _ _ _ _
            // _ _ _ _ _

            // P L A Y F
            // I R E X M
            // B C D G H
            // K N O Q S
            // T U V W Z
            if modus == &CryptModus::Encrypt {
                // moving right
                if a_sq_pos.column == 4 {
                    a_crypted_idx = a_sq_pos.row * 5;
                } else {
                    a_crypted_idx = a_sq_pos.row * 5 + a_sq_pos.column + 1;
                }
                if b_sq_pos.column == 4 {
                    b_crypted_idx = b_sq_pos.row * 5;
                } else {
                    b_crypted_idx = b_sq_pos.row * 5 + b_sq_pos.column + 1;
                }
            } else {
                // decrypt
                // moving left
                if a_sq_pos.column == 0 {
                    a_crypted_idx = (a_sq_pos.row * 5) + 4;
                } else {
                    a_crypted_idx = a_sq_pos.row * 5 + a_sq_pos.column - 1;
                }
                if b_sq_pos.column == 0 {
                    b_crypted_idx = (b_sq_pos.row * 5) + 4;
                } else {
                    b_crypted_idx = b_sq_pos.row * 5 + b_sq_pos.column - 1;
                }
            }
        }
        let a_crypted: char = match self.key.get(a_crypted_idx as usize) {
            Some(c) => *c,
            None => '*',
        };
        let b_crypted: char = match self.key.get(b_crypted_idx as usize) {
            Some(c) => *c,
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
        modus: &CryptModus,
    ) -> Result<String, CharNotInKeyError> {
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

    /// Encrypts a string. Note as the PlayFair cipher is only able to encrypt the
    /// characters A-I and L-Z any spaces and J are cleared off.
    ///
    /// # Example
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Playfair_cipher>
    ///
    /// ```
    /// use playfair_cipher::{ciphers::PlayFairKey, errors::CharNotInKeyError};
    ///
    /// let pfc = PlayFairKey::new("playfair example");
    /// match pfc.encrypt("hide the gold in the tree stump") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "BMODZBXDNABEKUDMUIXMMOUVIF");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    pub fn encrypt(&self, payload: &str) -> Result<String, CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Encrypt)
    }

    /// Decrypts a string.
    ///
    /// # Example
    ///
    /// As described at <https://en.wikipedia.org/wiki/Playfair_cipher>
    ///
    /// ```
    /// use playfair_cipher::ciphers::PlayFairKey as PlayFairKey;
    /// use playfair_cipher::errors::CharNotInKeyError as CharNotInKeyError;
    ///
    /// let pfc = PlayFairKey::new("playfair example");
    /// match pfc.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMP");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };    
    ///
    /// ```
    pub fn decrypt(&self, payload: &str) -> Result<String, CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Decrypt)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_payload() {
        let payload = Payload::new("I would like 4 tins of jam.");
        assert_eq!(payload.payload, "IWOULDLIKETINSOFIAM");
        // becomes "IWOULDLIKETINSOFIAM"
    }

    #[test]
    fn test_key_gen_empty_key() {
        let pfk = PlayFairKey::new("");
        assert_eq!(
            pfk.key,
            vec![
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
                'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
            ]
        )
    }

    #[test]
    fn test_key_gen_simple() {
        let pfk = PlayFairKey::new("simple");
        assert_eq!(
            pfk.key,
            vec![
                'S', 'I', 'M', 'P', 'L', 'E', 'A', 'B', 'C', 'D', 'F', 'G', 'H', 'K', 'N', 'O',
                'Q', 'R', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
            ]
        )
    }

    #[test]
    fn test_key_gen_seecretisjj() {
        let pfk = PlayFairKey::new("seecretisJJ");
        assert_eq!(
            pfk.key,
            vec![
                'S', 'E', 'C', 'R', 'T', 'I', 'A', 'B', 'D', 'F', 'G', 'H', 'K', 'L', 'M', 'N',
                'O', 'P', 'Q', 'U', 'V', 'W', 'X', 'Y', 'Z'
            ]
        )
    }

    #[test]
    fn test_key_gen_zxy_and_so_on() {
        let pfk = PlayFairKey::new("ZYXWVUTSRQPONMLKJIHGFECA");
        assert_eq!(
            pfk.key,
            vec![
                'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O', 'N', 'M', 'L', 'K',
                'I', 'H', 'G', 'F', 'E', 'C', 'A', 'B', 'D'
            ]
        )
    }

    #[test]
    fn test_iterator() {
        let mut payload = Payload::new("my secret message");
        let mut digrams: Vec<[char; 2]> = Vec::new();

        loop {
            let digram = payload.next();
            let [a, b] = match digram {
                Some(d) => d,
                None => break,
            };
            digrams.push([a, b]);
        }
        assert_eq!(
            digrams,
            vec![
                ['M', 'Y'],
                ['S', 'E'],
                ['C', 'R'],
                ['E', 'T'],
                ['M', 'E'],
                ['S', 'X'],
                ['S', 'A'],
                ['G', 'E']
            ]
        );
    }
    #[test]
    fn test_encrypt_square_rule_one_char() {
        let pfx = PlayFairKey::new("secret");
        match pfx.encrypt("a") {
            Ok(s) => assert_eq!(s, "DV"),
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_position_map() {
        let pfx = PlayFairKey::new("playfair example");
        let valid_positions: Vec<SquarePosition> = vec![
            SquarePosition { row: 0, column: 0 },
            SquarePosition { row: 0, column: 1 },
            SquarePosition { row: 0, column: 2 },
            SquarePosition { row: 0, column: 3 },
            SquarePosition { row: 0, column: 4 },
            SquarePosition { row: 1, column: 0 },
            SquarePosition { row: 1, column: 1 },
            SquarePosition { row: 1, column: 2 },
            SquarePosition { row: 1, column: 3 },
            SquarePosition { row: 1, column: 4 },
            SquarePosition { row: 2, column: 0 },
            SquarePosition { row: 2, column: 1 },
            SquarePosition { row: 2, column: 2 },
            SquarePosition { row: 2, column: 3 },
            SquarePosition { row: 2, column: 4 },
            SquarePosition { row: 3, column: 0 },
            SquarePosition { row: 3, column: 1 },
            SquarePosition { row: 3, column: 2 },
            SquarePosition { row: 3, column: 3 },
            SquarePosition { row: 3, column: 4 },
            SquarePosition { row: 4, column: 0 },
            SquarePosition { row: 4, column: 1 },
            SquarePosition { row: 4, column: 2 },
            SquarePosition { row: 4, column: 3 },
            SquarePosition { row: 4, column: 4 },
        ];
        let mut valid_positions_iter = valid_positions.iter();
        let empty_must_be_sqrt_pos = SquarePosition {
            row: 43,
            column: 43,
        };
        for (counter, c) in pfx.key.into_iter().enumerate() {
            let must_be_sqrt_pos = match valid_positions_iter.next() {
                Some(t) => t,
                None => &empty_must_be_sqrt_pos,
            };
            let check_sqrt_pos = match pfx.key_map.get(&c) {
                Some(t) => t,
                None => EMPTY_SQ_POS,
            };
            assert_eq!(
                check_sqrt_pos.row, must_be_sqrt_pos.row,
                "row assertion failed at iteration {}",
                counter
            );
            assert_eq!(
                check_sqrt_pos.column, must_be_sqrt_pos.column,
                "column assertion failed at iteration {}",
                counter
            );
        }
    }

    #[test]
    fn test_crypt_square() {
        // as described under https://en.wikipedia.org/wiki/Playfair_cipher Example 1
        let pfc = PlayFairKey::new("playfair example");
        match pfc.crypt('H', 'I', &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, 'B');
                assert_eq!(digram_crypt.b, 'M');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('B', 'M', &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, 'H',
                    "decrypt B failed - transformed to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(
                    digram_crypt.b, 'I',
                    "decrypt M failed - transformed to {} ",
                    digram_crypt.b
                );
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_crypt_column() {
        let pfc = PlayFairKey::new("playfair example");

        match pfc.crypt('D', 'E', &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, 'O');
                assert_eq!(digram_crypt.b, 'D');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('O', 'D', &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, 'D');
                assert_eq!(digram_crypt.b, 'E');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('A', 'V', &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, 'E');
                assert_eq!(digram_crypt.b, 'A');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('E', 'A', &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, 'A');
                assert_eq!(digram_crypt.b, 'V', "A transforms to {}", digram_crypt.b);
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_crypt_row() {
        let pfc = PlayFairKey::new("playfair example");

        match pfc.crypt('E', 'X', &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, 'X',
                    "E transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, 'M');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('X', 'M', &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, 'E',
                    "X transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, 'X');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('I', 'M', &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, 'R',
                    "I transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, 'I');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt('R', 'I', &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, 'I',
                    "R transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, 'M');
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_encrypt() {
        let pfc = PlayFairKey::new("rust rules");
        match pfc.encrypt(&String::from("cratesio")) {
            Ok(crypt) => {
                assert_eq!(crypt, String::from("ETCUBRHP"));
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_decrypt() {
        let pfc = PlayFairKey::new("rustrules");
        match pfc.decrypt(&String::from("ETCUBRHP")) {
            Ok(crypt) => {
                assert_eq!(crypt, String::from("cratesio").to_uppercase());
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }
}
