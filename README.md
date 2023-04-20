# playfair_cipher
Implementation of the [PlayFair cipher](https://en.wikipedia.org/wiki/Playfair_cipher) - nothing special, nothing useful, just for fun. 


## Encrypt

```rust
use playfair_cipher::{ciphers::PlayFairKey, errors::CharNotInKeyError};

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
use playfair_cipher::ciphers::PlayFairKey as PlayFairKey;
use playfair_cipher::errors::CharNotInKeyError as CharNotInKeyError;

let pfc = PlayFairKey::new("playfair example");
match pfc.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF") {
  Ok(crypt) => {
    assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMP");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};    
```

That's it.

