# General

The crate contains the playfair, the two square and the four square ciphers.
Note all are pre computer cipers. Do not feel like
protecting data of any value with them. Any of those are crackable
in very short time.

# Basics on squares

The library offers two square sizes - 5 to 5 and 6 to 6. If using 5 to 5
the encryption is done with the basic setup of the square like this

```
A B C D E 
F G H I K 
L M N O P 
Q R S T U 
V W X Y Z
```

Only characters contained in the square can be encrypted. Which means with the 
5 to 5 square there are no digits encryptable. 

If the library is used with the 6 to 6 square the basic setup is like this

```
A B C D E F 
G H I J K L 
M N O P Q R 
S T U V W X 
Y Z 0 1 2 3 
4 5 6 7 8 9
```

Only characters in the square can be encrypted, but with this square digits 0-9 and
the character J is encryptable.

This charactersitics applies to the TwoSquare and the FourSquare cipher aswell. The only 
differ in the number of squares used.

When using method encrypt the payload is converted to uppercase and any character not within the 
the square is removed.

So you don't need to clear off not encryptable characters when using
this library.

# Passkeys

To use the ciphers as they where intended to be used one must seed them with a passkey. Empty passkeys 
are possible. Not encryptable characters in the passkey are removed again. Note the removement happends
stealthy - no error is raised.

# playfair_cipher
Implementation of the [PlayFair cipher](https://en.wikipedia.org/wiki/Playfair_cipher) - nothing special, nothing useful, just for fun. 




## Encrypt

```rust
use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
use use playfair_cipher::cryptable::Cypher;

let pfc = PlayFairKey::new("playfair example");
match pfc.encrypt("hide the gold in the tree stump") {
  Ok(crypt) => {
    assert_eq!(crypt, "BMODZBXDNABEKUDMUIXMMOUVIF");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

```rust
use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
use playfair_cipher::errors::CharNotInKeyError as CharNotInKeyError;
use playfair_cipher::cryptable::Cypher;

let pfc = PlayFairKey::new("playfair example");
match pfc.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF") {
  Ok(crypt) => {
    assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMP");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
}; 
```

# four_square_ciper
Implementation of the [FourSquare cipher](https://en.wikipedia.org/wiki/Four-square_cipher) - nothing special, nothing useful, just for fun.

## Encrypt

```rust
use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let fsq = FourSquare::new("EXAMPLE", "KEYWORD");
match fsq.encrypt("joe") {
  Ok(crypt) => {
    assert_eq!(crypt, "DIAZ");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

```rust
use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let fsq = FourSquare::new("EXAMPLE", "KEYWORD");
match fsq.decrypt("DIAZ") {
  Ok(crypt) => {
    assert_eq!(crypt, "IOEX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```
# two_square_ciper
Implementation of the [TwoSquare cipher](https://en.wikipedia.org/wiki/Two-square_cipher) - nothing special, nothing useful, just for fun.

## Encrypt

```rust
use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let tsq = TwoSquare::new("EXAMPLE", "KEYWORD");
match tsq.encrypt("joe") {
  Ok(crypt) => {
    assert_eq!(crypt, "NYMT");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

```rust
use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let tsq = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
match tsq.decrypt("NYMT") {
  Ok(crypt) => {
    assert_eq!(crypt, "IOEX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

That's it.

