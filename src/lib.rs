//! This is the implentation of the PlayFair cipher as described
//! <https://en.wikipedia.org/wiki/Playfair_cipher>
//!

use std::collections::HashMap;
use std::{error::Error, fmt};

const KEY_CARS: &str = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

const KEY_LENGTH: usize = 25;

const EMPTY_SQ_POS: &SquarePosition = &SquarePosition {
    column: 42,
    row: 42,
};

/// Error indicating a character in the given string could not be looked up in the
/// PlayFairKey. If this occours any operation is stopped.
#[derive(Debug, Clone)]
pub struct CharNotInKeyError {
    error: String,
}

impl fmt::Display for CharNotInKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Oh no, something bad went down")
    }
}
impl Error for CharNotInKeyError {}
impl CharNotInKeyError {
    fn new(error: String) -> Self {
        CharNotInKeyError { error }
    }
}

/// Struct represents a PlayFaire Cypher. It's holding the key and the
/// position of any character in the key.
///
#[derive(Debug)]
pub struct PlayFairKey {
    /// PlayFair 5*5 matrix
    ///
    key: Vec<char>,
    key_map: HashMap<char, SquarePosition>,
}

/// For each character from the key, its position within the imaged square stored in
/// this struct.
/// Having this square:
///        columns
///        0 1 2 3 4
///  row 0 _ _ _ _ _
///  row 1 _ _ _ _ _
///  row 2 _ _ _ _ _
///  row 3 _ _ _ _ _
///  row 4 _ _ _ _ _
#[derive(Debug)]
struct SquarePosition {
    row: u8,
    column: u8,
}

struct CryptResult {
    a: char,
    b: char,
}

#[derive(PartialEq)]
enum CryptModus {
    Encrypt,
    Decrypt,
}

impl PlayFairKey {
    /// Constructs a new PlayFaire cipher.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::PlayFairKey;
    ///
    /// let pfc = PlayFairKey::new("Secret");
    /// ```
    pub fn new(key: &str) -> Self {
        let raw_key: String = key.to_uppercase().replace(' ', "").replace('J', "I") + KEY_CARS;

        let mut temp_key = String::with_capacity(KEY_LENGTH);
        let mut counter = 0;
        // Position counter reflects the position in the
        // imaginary 5*5 square. So to be consistent, it start from 0
        let mut row_counter = 0;
        let mut col_counter = 0;
        let mut key_map: HashMap<char, SquarePosition> = HashMap::new();

        while counter < raw_key.len() && temp_key.len() < KEY_LENGTH {
            if col_counter > 4 {
                col_counter = 0;
                row_counter += 1;
            }

            let temp_key_char = &raw_key[counter..counter + 1];
            counter += 1;
            if temp_key.contains(temp_key_char) {
                continue;
            } else {
                temp_key += temp_key_char;
                let temp_key_char_vec: Vec<char> = temp_key_char.chars().collect();

                key_map.insert(
                    match temp_key_char_vec.first() {
                        Some(k) => *k,
                        None => '*',
                    },
                    SquarePosition {
                        row: row_counter,
                        column: col_counter,
                    },
                );
                col_counter += 1;
            }
        }

        PlayFairKey {
            key: temp_key.chars().collect(),
            key_map,
        }
    }

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
                "{} was not found in {:?}",
                a, &self.key
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "{} was not found in {:?}",
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

            // exmaple B M
            // P L A Y F
            // I R E X M
            // B C D G H
            // K N O Q S
            // T U V W Z
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
        let char_tuples = into_pairs(payload);
        let mut payload_encrypted = String::new();
        for [a, b] in char_tuples {
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
    /// ```
    /// use playfair_cipher::{PlayFairKey, CharNotInKeyError};
    ///
    /// let pfc = PlayFairKey::new("Secret");
    /// match pfc.encrypt(&String::from("Even more secret")) {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, String::from("SWSOIUTCECRTCS"));
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    ///
    /// ```
    pub fn encrypt(&self, payload: &str) -> Result<String, CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Encrypt)
    }

    /// Decrypts a string.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::{PlayFairKey, CharNotInKeyError};
    ///
    /// let pfc = PlayFairKey::new("Secret");
    /// match pfc.decrypt("SWSOIUTCECRTCS") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, String::from("EVENMORESECRET"));
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };    
    ///
    /// ```
    pub fn decrypt(&self, payload: &str) -> Result<String, CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Decrypt)
    }
}

fn into_pairs(payload: &str) -> Vec<[char; 2]> {
    let payload_uppercase = payload.to_uppercase().replace(' ', "").replace('J', "I");
    let mut char_cuples: Vec<[char; 2]> = Vec::new();
    let mut counter = 0;
    while counter < payload_uppercase.len() {
        let first_member = &payload_uppercase[counter..counter + 1];
        // do not overrun string bounderies.
        let second_member = match counter + 2 <= payload_uppercase.len() {
            true => &payload_uppercase[counter + 1..counter + 2],
            false => "X",
        };
        //&payload[counter + 1..counter + 2];
        if first_member == second_member {
            // first and second are the same, so stuff it
            let char_list: Vec<char> = first_member.chars().collect();
            char_cuples.push([char_list[0], 'X']);
            counter += 1;
        } else {
            let char_list_first: Vec<char> = first_member.chars().collect();
            let char_list_second: Vec<char> = second_member.chars().collect();
            char_cuples.push([char_list_first[0], char_list_second[0]]);
            counter += 2;
        }
    }
    char_cuples
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_into_pairs() {
        assert_eq!(
            into_pairs("my secret message"),
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
        let mut counter = 0;
        for c in pfx.key {
            let must_be_sqrt_pos = match valid_positions_iter.next() {
                Some(t) => t,
                None => &empty_must_be_sqrt_pos,
            };
            let check_sqrt_pos = match pfx.key_map.get(&c) {
                Some(t) => t,
                None => &EMPTY_SQ_POS,
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
            counter += 1;
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
