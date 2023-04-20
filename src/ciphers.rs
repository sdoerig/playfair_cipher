use crate::structs::SquarePosition;
use std::collections::HashMap;

const KEY_CARS: &str = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

const KEY_LENGTH: usize = 25;

/// Struct represents a PlayFaire Cypher. It's holding the key and the
/// position of any character in the key.
///
#[derive(Debug)]
pub struct PlayFairKey {
    /// PlayFair 5*5 matrix
    ///
    pub(crate) key: Vec<char>,
    pub(crate) key_map: HashMap<char, SquarePosition>,
}

impl PlayFairKey {
    /// Constructs a new PlayFaire cipher.
    ///
    /// # Example
    ///
    /// ```
    /// use playfair_cipher::ciphers::PlayFairKey as PlayFairKey;
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
}
