use crate::playfair;

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
            } else if ("A"..="Z").contains(&character) {
                payload_cleared += character;
            }
            counter += 1;
        }
        Payload {
            payload: payload_cleared,
            counter: 0,
        }
    }
    pub(crate) fn crypt_payload(
        &mut self,
        cipher: &impl playfair::Crypt,
        modus: &crate::structs::CryptModus,
    ) -> Result<String, crate::errors::CharNotInKeyError> {
        let mut payload_encrypted = String::new();

        loop {
            let digram = self.next();
            let [a, b] = match digram {
                Some(d) => d,
                None => break,
            };
            match cipher.crypt(a, b, modus) {
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
