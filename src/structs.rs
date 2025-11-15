use std::collections::{hash_map, HashMap};

use crate::cryptable::Crypt;

// For each character from the key, its position within the imaged square stored in
// this struct.
// Having this square
//
//        columns
//        0 1 2 3 4
//  row 0 _ _ _ _ _
//  row 1 _ _ _ _ _
//  row 2 _ _ _ _ _
//  row 3 _ _ _ _ _
//  row 4 _ _ _ _ _
#[derive(Debug)]
pub(crate) struct SquarePosition {
    pub row: usize,
    pub column: usize,
}

pub(crate) struct CryptResult {
    pub a: String,
    pub b: String,
}

#[derive(Debug)]
pub struct Tokens {
    pub(crate) tokens: String,
    tokens_replaced_by: HashMap<String, String>,
    pub(crate) split_by: String,
    padding: String,
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

impl Tokens {
    pub fn new(
        tokens: &str,
        tokens_replaced_by: HashMap<String, String>,
        split_by: &str,
        padding: &str,
    ) -> Self {
        Tokens {
            tokens: tokens.to_string(),
            tokens_replaced_by,
            split_by: split_by.to_string(),
            padding: padding.to_string(),
        }
    }

    pub(crate) fn payload(&self, payload: &str) -> String {
        //let mut counter: usize = 0;
        let mut payload_cleared = String::with_capacity(payload.len());
        let payload_uc = payload.to_uppercase();
        for character in payload_uc.split(&self.split_by) {
            let character_replaced = match self.tokens_replaced_by.get(character) {
                Some(s) => s,
                None => character,
            };

            //let character = &payload_uc[counter..counter + 1];
            if self.tokens.contains(character_replaced) {
                payload_cleared += character_replaced;
            }
            //counter += 1;
        }
        payload_cleared
    }
}

impl Payload {
    pub(crate) fn new(payload: String) -> Self {
        Payload {
            payload,
            counter: 0,
        }
    }
    pub(crate) fn crypt_payload(
        &mut self,
        cipher: &impl Crypt,
        modus: &crate::structs::CryptModus,
    ) -> Result<String, crate::errors::CharNotInKeyError> {
        let mut payload_encrypted = String::new();

        loop {
            let digram = self.next();
            let [a, b] = match digram {
                Some(d) => d,
                None => break,
            };
            match cipher.crypt(&a, &b, modus) {
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

impl Iterator for Payload {
    type Item = [String; 2];

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
                let char_list: Vec<String> = vec![String::from(first_member)];

                self.counter += 1;
                Some([String::from(first_member), String::from("X")])
            } else {
                let char_list_first: Vec<char> = first_member.chars().collect();
                let char_list_second: Vec<char> = second_member.chars().collect();

                self.counter += 2;
                Some([String::from(first_member), String::from(second_member)])
            }
        } else {
            None
        }
    }
}
