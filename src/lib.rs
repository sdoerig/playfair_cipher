//! # About
//! The crate contains the [playfair]((https://en.wikipedia.org/wiki/Playfair_cipher)),
//! the [two square](https://en.wikipedia.org/wiki/Two-square_cipher) and the
//! [four square](https://en.wikipedia.org/wiki/Four-square_cipher) cipers.
//! Note all of the are pre computer cipers. Do not feel like
//! protecting data of any value with them. They are crackable
//! in very short time. So this crate implements something historical and is not inteded
//! to be used in a serious context.
//!
//! As the ciphers playfair, two square and four square are closely related to each other
//! they are implemented in the same crate, based on the playfair implementation. Two square
//! and four square are in this implementation just wrapped aroud playfair as they are just using
//! several playfair squares.
//!
//! Any ciper can be used with a 5 to 5 or 6 to 6 matrix.
//!
//! # Example 5 to 5
//! ```text
//! A B C D E
//! F G H I K
//! L M N O P
//! Q R S T U
//! V W X Y Z
//! ```
//! When using the method encrypt the payload is converted to uppercase
//! and any character not within the range A..I and K..Z is ignored.
//! E.g. "I would like 4 tins of jam." becomes "IWOULDLIKETINSOFIAM".
//! So you don't need to clear off not encryptable characters when using
//! this library. This is the classical cipher as proposed 1854.
//!
//! # Example 6 to 6
//! ```text
//! A B C D E F
//! G H I J K L
//! M N O P Q R
//! S T U V W X
//! Y Z 0 1 2 3
//! 4 5 6 7 8 9
//! ```
//! With the 6 to 6 matrix, the senence "I would like 4 tins of jam."
//! becomes "IWOULDLIKE4TINSOFJAM". So the 6 to 6 matrix allows to include
//! digits too.
//!
pub mod cryptable;
pub mod errors;
pub mod four_square;
pub mod playfair;
mod structs;
pub mod two_square;
