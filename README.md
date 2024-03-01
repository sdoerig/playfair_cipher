# General

The crate contains the playfair, the two square and the four square cipers.
Note all are pre computer cipers. Do not feel like
protecting data of any value with them. Any of those are crackable
in very short time.

When using the method encrypt the payload is converted to uppercase
and any character not within the range A..I and K..Z is ignored.
E.g. "I would like 4 tins of jam." becomes "IWOULDLIKETINSOFIAM".
So you don't need to clear off not encryptable characters when using
this library.

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

let tsq = TwoSquare::new("EXAMPLE", "KEYWORD");
match tsq.decrypt("NYMT") {
  Ok(crypt) => {
    assert_eq!(crypt, "IOEX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

That's it.

