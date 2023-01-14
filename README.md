# playfair_cipher
Implementation of the [PlayFair cipher](https://en.wikipedia.org/wiki/Playfair_cipher) - nothing special, nothing useful, just for fun. 


## Encrypt

```rust
use playfair_cipher::{PlayFairKey, CharNotInKeyError};

let pfc = PlayFairKey::new("playfair example");
match pfc.encrypt(&String::from("hide the gold in the tree stump")) {
  Ok(crypt) => {
    assert_eq!(crypt, String::from("BMODZBXDNABEKUDMUIXMMOUVIF"));
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

```rust
use playfair_cipher::{PlayFairKey, CharNotInKeyError};

let pfc = PlayFairKey::new("playfair example");
match pfc.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF") {
  Ok(crypt) => {
    assert_eq!(crypt, String::from("HIDETHEGOLDINTHETREXESTUMP"));
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

That's it.

