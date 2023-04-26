# playfair_cipher
Implementation of the [PlayFair cipher](https://en.wikipedia.org/wiki/Playfair_cipher) - nothing special, nothing useful, just for fun. 

Do not use them to crypt data of any value, since both of them are pre computer ciphers and so today very vulnerable.


## Encrypt

```rust
use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
use crate::playfair_cipher::playfair::Cypher;

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
use playfair_cipher::playfair::Cypher;

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
use playfair_cipher::playfair::Cypher;

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
use crate::playfair_cipher::playfair::Cypher;

let fsq = FourSquare::new("EXAMPLE", "KEYWORD");
match fsq.decrypt("DIAZ") {
  Ok(crypt) => {
    assert_eq!(crypt, "IOEX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

That's it.

