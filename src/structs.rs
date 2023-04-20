use std::collections::HashMap;

const KEY_CARS: &str = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

const KEY_LENGTH: usize = 25;

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
pub(crate) struct SquarePosition {
    pub row: u8,
    pub column: u8,
}

pub(crate) struct CryptResult {
    pub a: char,
    pub b: char,
}

pub(crate) struct Payload {
    pub payload: String,
    pub counter: usize,
}

#[derive(PartialEq)]
pub(crate) enum CryptModus {
    Encrypt,
    Decrypt,
}

impl Payload {
    pub(crate) fn new(payload: &str) -> Self {
        let mut counter: usize = 0;
        let mut payload_cleared = String::with_capacity(payload.len());
        let payload_uc = payload.to_uppercase();
        while counter < payload_uc.len() {
            let character = &payload_uc[counter..counter + 1];
            if character == "J" {
                payload_cleared += "I";
            } else if character >= "A" && character <= "Z" {
                payload_cleared += character;
            }
            counter += 1;
        }
        Payload {
            payload: payload_cleared,
            counter: 0,
        }
    }
}

impl Iterator for Payload {
    type Item = [char; 2];

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter < self.payload.len() {
            let first_member = &self.payload[self.counter..self.counter + 1];
            // do not overrun string bounderies.
            let second_member = match self.counter + 2 <= self.payload.len() {
                true => &self.payload[self.counter + 1..self.counter + 2],
                false => "X",
            };

            //&payload[counter + 1..counter + 2];
            if first_member == second_member {
                // first and second are the same, so stuff it
                let char_list: Vec<char> = first_member.chars().collect();

                self.counter += 1;
                Some([char_list[0], 'X'])
            } else {
                let char_list_first: Vec<char> = first_member.chars().collect();
                let char_list_second: Vec<char> = second_member.chars().collect();

                self.counter += 2;
                Some([char_list_first[0], char_list_second[0]])
            }
        } else {
            None
        }
    }
}

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
    /// use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
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
