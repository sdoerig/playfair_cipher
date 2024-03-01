//! The crate contains the playfair, the two square and the four square cipers.
//! Note all of the are pre computer cipers. Do not feel like
//! protecting data of any value with them. Any of them is crackable
//! in very short time.
//!
//! When using the method encrypt the payload is converted to uppercase
//! and any character not within the range A..I and K..Z is ignored.
//! E.g. "I would like 4 tins of jam." becomes "IWOULDLIKETINSOFIAM".
//! So you don't need to clear off not encryptable characters when using
//! this library.
//!
pub mod cryptable;
pub mod errors;
pub mod four_square;
pub mod playfair;
mod structs;
pub mod two_square;
