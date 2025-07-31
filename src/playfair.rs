//! This is the implentation of the PlayFair cipher as described
//! <https://en.wikipedia.org/wiki/Playfair_cipher>
//!
//!
use crate::cryptable::{Cipher, Crypt};
use crate::errors::CharNotInKeyError;

use crate::structs::{CryptModus, CryptResult, Payload, SquarePosition, Tokens};

pub(crate) const EMPTY_SQ_POS: &SquarePosition = &SquarePosition {
    column: 42,
    row: 42,
};

use std::collections::HashMap;

const KEY_CHARS: &str = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
const KEY_CHARS_A_TO_Z_0_TO_9: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const KEY_EMOTJI_6_TO_6: &str =
    "😀😃😄😁😆😅😂🤣🥲🥹☺️😊😇🙂🙃😉😌😍🥰😘😗😙😚😋😛😝😜🤪🤨🧐🤓😎🥸🤩🥳🙂‍↕️";

/// Struct represents a PlayFaire Cipher. It"s holding the key and the
/// position of any character in the key.
///
#[derive(Debug)]
pub struct PlayFairKey {
    /// PlayFair 5*5 matrix
    ///
    pub(crate) key: Vec<String>,
    pub(crate) key_map: HashMap<String, SquarePosition>,
    pub(crate) row_len: usize,
    pub(crate) square: usize,
    pub(crate) tokens: Tokens,
}

impl PlayFairKey {
    /// Constructs a new PlayFaire cipher based on a
    /// 5 to 5 square. J is replaced by I, no digits. Passkey can only
    /// contain A-I and K-Z.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
    ///
    /// let pfc = PlayFairKey::new_5_to_5("Secret");
    /// ```
    pub fn new_5_to_5(key: &str) -> Self {
        let mut tokens_replaced_by: HashMap<String, String> = HashMap::new();
        tokens_replaced_by.insert("J".to_string(), "I".to_string());
        create_play_fair_key(key, Tokens::new(KEY_CHARS, tokens_replaced_by))
    }

    /// Constructs a new PlayFaire cipher based on a
    /// 6 to 6 square. A-Z and 0-9 are encryptable too.
    /// Passkey can contain A-Z and 0-9.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
    ///
    /// let pfc = PlayFairKey::new_6_to_6("Secret");
    /// ```
    pub fn new_6_to_6(key: &str) -> Self {
        let tokens_replaced_by: HashMap<String, String> = HashMap::new();
        create_play_fair_key(
            key,
            Tokens::new(KEY_CHARS_A_TO_Z_0_TO_9, tokens_replaced_by),
        )
    }
    /// Constructs a new PlayFaire cipher based on a
    /// 6 to 6 square. A-Z and 0-9 are encryptable too.
    /// Passkey can contain A-Z and 0-9.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
    ///
    /// let pfc = PlayFairKey::new_6_to_6("Secret");
    /// ```
    pub fn new_emotji_6_to_6(key: &str) -> Self {
        let tokens_replaced_by: HashMap<String, String> = HashMap::new();
        create_play_fair_key(key, Tokens::new(KEY_EMOTJI_6_TO_6, tokens_replaced_by))
    }
}

fn create_play_fair_key(key: &str, tokens: Tokens) -> PlayFairKey {
    let raw_key: String = key.to_uppercase() + &tokens.tokens;
    let mut key_list: Vec<String> = Vec::new();

    let row_len: usize = match tokens.tokens.len() {
        25 => 4,
        _ => 5,
    };

    // Position counter reflects the position in the
    // imaginary 5*5 square. So to be consistent, it start from 0
    let mut row_counter = 0;
    let mut col_counter = 0;
    let mut key_map: HashMap<String, SquarePosition> = HashMap::new();
    for token in raw_key.split("") {
        if col_counter > row_len {
            col_counter = 0;
            row_counter += 1;
        }
        if key_map.contains_key(token) || !tokens.tokens.contains(token) || token.is_empty() {
            continue;
        } else {
            key_list.push(token.to_string());

            key_map.insert(
                token.to_string(),
                SquarePosition {
                    row: row_counter,
                    column: col_counter,
                },
            );
            col_counter += 1;
        }
    }

    PlayFairKey {
        key: key_list,
        key_map,
        row_len,
        square: row_len + 1,
        tokens,
    }
}

impl Crypt for PlayFairKey {
    fn crypt(
        &self,
        a: &str,
        b: &str,
        modus: &CryptModus,
    ) -> Result<CryptResult, CharNotInKeyError> {
        let a_sq_pos = match self.key_map.get(a) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        let b_sq_pos = match self.key_map.get(b) {
            Some(p) => p,
            None => EMPTY_SQ_POS,
        };
        if a_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - {} was not found in key {:?}",
                a, &self.key
            )));
        } else if b_sq_pos.column == EMPTY_SQ_POS.column {
            return Err(CharNotInKeyError::new(format!(
                "Only chars A-Z possible - {} was not found in key {:?}",
                b, &self.key
            )));
        }
        let mut a_crypted_idx: usize = 0;
        let mut b_crypted_idx: usize = 0;
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

            a_crypted_idx = a_sq_pos.row * self.square + b_sq_pos.column;
            b_crypted_idx = b_sq_pos.row * self.square + a_sq_pos.column;
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
                if a_sq_pos.row == self.row_len {
                    // In the last row - so going back to row 0
                    a_crypted_idx = a_sq_pos.column;
                } else {
                    a_crypted_idx = (a_sq_pos.row + 1) * self.square + a_sq_pos.column
                }
                if b_sq_pos.row == self.row_len {
                    // In the last row - so going back to row 0
                    b_crypted_idx = b_sq_pos.column;
                } else {
                    b_crypted_idx = (b_sq_pos.row + 1) * self.square + b_sq_pos.column
                }
            } else {
                // Decrypting
                if a_sq_pos.row == 0 {
                    a_crypted_idx = 20 + a_sq_pos.column;
                } else {
                    a_crypted_idx = (a_sq_pos.row - 1) * self.square + a_sq_pos.column;
                }
                if b_sq_pos.row == 0 {
                    b_crypted_idx = 20 + b_sq_pos.column;
                } else {
                    b_crypted_idx = (b_sq_pos.row - 1) * self.square + b_sq_pos.column;
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
                if a_sq_pos.column == self.row_len {
                    a_crypted_idx = a_sq_pos.row * self.square;
                } else {
                    a_crypted_idx = a_sq_pos.row * self.square + a_sq_pos.column + 1;
                }
                if b_sq_pos.column == self.row_len {
                    b_crypted_idx = b_sq_pos.row * self.square;
                } else {
                    b_crypted_idx = b_sq_pos.row * self.square + b_sq_pos.column + 1;
                }
            } else {
                // decrypt
                // moving left
                if a_sq_pos.column == 0 {
                    a_crypted_idx = (a_sq_pos.row * self.square) + self.row_len;
                } else {
                    a_crypted_idx = a_sq_pos.row * self.square + a_sq_pos.column - 1;
                }
                if b_sq_pos.column == 0 {
                    b_crypted_idx = (b_sq_pos.row * self.square) + self.row_len;
                } else {
                    b_crypted_idx = b_sq_pos.row * self.square + b_sq_pos.column - 1;
                }
            }
        }
        let a_crypted = match self.key.get(a_crypted_idx) {
            Some(c) => c,
            None => &String::from("*"),
        };
        let b_crypted = match self.key.get(b_crypted_idx) {
            Some(c) => c,
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
        let mut payload_iter = Payload::new(self.tokens.payload(payload));

        payload_iter.crypt_payload(self, modus)
    }

    fn playload(&self, payload: &str) -> String {
        self.tokens.payload(payload)
    }
}

impl Cipher for PlayFairKey {
    /// Encrypts a string. Note as the PlayFair cipher is only able to encrypt the
    /// characters A-I and L-Z any spaces and J are cleared off.
    ///
    /// # Example 5 to 5
    ///  
    /// As described at <https://en.wikipedia.org/wiki/Playfair_cipher>
    ///
    /// ```
    /// use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let pfc = PlayFairKey::new_5_to_5("playfair example");
    /// match pfc.encrypt("hide the gold in the tree stump") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "BMODZBXDNABEKUDMUIXMMOUVIF");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    ///     
    /// # Example 6 to 6
    ///
    /// ```
    /// use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let pfc = PlayFairKey::new_6_to_6("play 3645 fair 8760 example");
    /// match pfc.encrypt("hide the gold in the tree stump at 5 o'clock.") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "SXG0SJGQW5H5OUGX2MXMXQUN733Q0WDPNDHB");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    fn encrypt(&self, payload: &str) -> Result<String, CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Encrypt)
    }

    /// Decrypts a string.
    ///
    /// # Example 5 to 5
    ///
    /// As described at <https://en.wikipedia.org/wiki/Playfair_cipher>
    ///
    /// ```
    /// use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
    /// use playfair_cipher::errors::CharNotInKeyError as CharNotInKeyError;
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let pfc = PlayFairKey::new_5_to_5("playfair example");
    /// match pfc.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMP");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };    
    ///
    /// ```
    ///
    /// # Example 6 to 6
    ///
    /// ```
    /// use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
    /// use playfair_cipher::cryptable::Cypher;
    ///
    /// let pfc = PlayFairKey::new_6_to_6("play 3645 fair 8760 example");
    /// match pfc.decrypt("SXG0SJGQW5H5OUGX2MXMXQUN733Q0WDPNDHB") {
    ///   Ok(crypt) => {
    ///     assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMPAT5OCLOCKX");
    ///   }
    ///   Err(e) => panic!("CharNotInKeyError {}", e),
    /// };
    /// ```
    fn decrypt(&self, payload: &str) -> Result<String, CharNotInKeyError> {
        self.crypt_payload(payload, &CryptModus::Decrypt)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_payload() {
        let pfk = PlayFairKey::new_5_to_5("");
        let payload = Payload::new(pfk.tokens.payload("I would like 4 tins of jam."));
        assert_eq!(
            payload.payload, "IWOULDLIKETINSOFIAM",
            "{}",
            pfk.tokens.tokens
        );
        // becomes "IWOULDLIKETINSOFIAM"
    }
    #[test]
    fn test_payload_6_to_6() {
        let pfk = PlayFairKey::new_6_to_6("");
        let payload = Payload::new(pfk.tokens.payload("I would like 4 tins of jam."));
        assert_eq!(payload.payload, "IWOULDLIKE4TINSOFJAM");
        // becomes "IWOULDLIKETINSOFIAM"
    }

    #[test]
    fn test_payload_6_to_6_emotji() {
        let pfk = PlayFairKey::new_emotji_6_to_6("");
        let payload = Payload::new(pfk.tokens.payload("😀😃😄😁😆😅😂🤣🥲🥹☺️🤠😈👿👹"));
        assert_eq!(payload.payload, "😀😃😄😁😆😅😂🤣🥲🥹☺️");
        // becomes "IWOULDLIKETINSOFIAM"
    }

    #[test]
    fn test_key_gen_empty_key() {
        let pfk = PlayFairKey::new_5_to_5("");
        assert_eq!(
            pfk.key,
            vec![
                "A", "B", "C", "D", "E", "F", "G", "H", "I", "K", "L", "M", "N", "O", "P", "Q",
                "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
            ]
        )
    }

    #[test]
    fn test_key_gen_empty_key_6_to_6() {
        let pfk = PlayFairKey::new_6_to_6("");
        assert_eq!(
            pfk.key,
            vec![
                "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
                "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5",
                "6", "7", "8", "9"
            ]
        )
    }

    #[test]
    fn test_key_gen_simple() {
        let pfk = PlayFairKey::new_5_to_5("simple");
        assert_eq!(
            pfk.key,
            vec![
                "S", "I", "M", "P", "L", "E", "A", "B", "C", "D", "F", "G", "H", "K", "N", "O",
                "Q", "R", "T", "U", "V", "W", "X", "Y", "Z"
            ]
        )
    }

    #[test]
    fn test_key_gen_seecretisjj() {
        let pfk = PlayFairKey::new_5_to_5("seecretisJJ");
        assert_eq!(
            pfk.key,
            vec![
                "S", "E", "C", "R", "T", "I", "A", "B", "D", "F", "G", "H", "K", "L", "M", "N",
                "O", "P", "Q", "U", "V", "W", "X", "Y", "Z"
            ]
        )
    }

    #[test]
    fn test_key_gen_seecretisjj_6_to_6() {
        let pfk = PlayFairKey::new_6_to_6("seecretisJJ");
        assert_eq!(
            pfk.key,
            vec![
                "S", "E", "C", "R", "T", "I", "J", "A", "B", "D", "F", "G", "H", "K", "L", "M",
                "N", "O", "P", "Q", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5",
                "6", "7", "8", "9"
            ]
        )
    }

    #[test]
    fn test_key_gen_zxy_and_so_on() {
        let pfk = PlayFairKey::new_5_to_5("ZYXWVUTSRQPONMLKJIHGFECA");
        assert_eq!(
            pfk.key,
            vec![
                "Z", "Y", "X", "W", "V", "U", "T", "S", "R", "Q", "P", "O", "N", "M", "L", "K",
                "I", "H", "G", "F", "E", "C", "A", "B", "D"
            ]
        )
    }

    #[test]
    fn test_iterator() {
        let pfk = PlayFairKey::new_5_to_5("key");
        let mut payload = Payload::new(pfk.tokens.payload("my secret message"));
        let mut digrams: Vec<[String; 2]> = Vec::new();

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
                ["M", "Y"],
                ["S", "E"],
                ["C", "R"],
                ["E", "T"],
                ["M", "E"],
                ["S", "X"],
                ["S", "A"],
                ["G", "E"]
            ]
        );
    }
    #[test]
    fn test_encrypt_square_rule_one_char() {
        let pfx = PlayFairKey::new_5_to_5("secret");
        match pfx.encrypt("a") {
            Ok(s) => assert_eq!(s, "DV"),
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_position_map() {
        let pfx = PlayFairKey::new_5_to_5("playfair example");
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
        let pfc = PlayFairKey::new_5_to_5("playfair example");
        match pfc.crypt("H", "I", &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, "B");
                assert_eq!(digram_crypt.b, "M");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("B", "M", &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, "H",
                    "decrypt B failed - transformed to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(
                    digram_crypt.b, "I",
                    "decrypt M failed - transformed to {} ",
                    digram_crypt.b
                );
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_crypt_column() {
        let pfc = PlayFairKey::new_5_to_5("playfair example");

        match pfc.crypt("D", "E", &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, "O");
                assert_eq!(digram_crypt.b, "D");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("O", "D", &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, "D");
                assert_eq!(digram_crypt.b, "E");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("A", "V", &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, "E");
                assert_eq!(digram_crypt.b, "A");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("E", "A", &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(digram_crypt.a, "A");
                assert_eq!(digram_crypt.b, "V", "A transforms to {}", digram_crypt.b);
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_crypt_row() {
        let pfc = PlayFairKey::new_5_to_5("playfair example");

        match pfc.crypt("E", "X", &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, "X",
                    "E transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, "M");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("X", "M", &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, "E",
                    "X transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, "X");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("I", "M", &CryptModus::Encrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, "R",
                    "I transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, "I");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
        match pfc.crypt("R", "I", &CryptModus::Decrypt) {
            Ok(digram_crypt) => {
                assert_eq!(
                    digram_crypt.a, "I",
                    "R transfers to {} key {:?}",
                    digram_crypt.a, pfc.key
                );
                assert_eq!(digram_crypt.b, "M");
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_encrypt() {
        let pfc = PlayFairKey::new_5_to_5("rust rules");
        match pfc.encrypt(&String::from("cratesio")) {
            Ok(crypt) => {
                assert_eq!(crypt, String::from("ETCUBRHP"));
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }

    #[test]
    fn test_decrypt() {
        let pfc = PlayFairKey::new_5_to_5("rustrules");
        match pfc.decrypt(&String::from("ETCUBRHP")) {
            Ok(crypt) => {
                assert_eq!(crypt, String::from("cratesio").to_uppercase());
            }
            Err(e) => panic!("CharNotInKeyError {}", e),
        };
    }
}
