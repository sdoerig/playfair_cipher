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

With the 6 to 6 square the characters A-Z and 0-9 are encryptable.

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

# Benchmarking

The library can be benchmarked using [criterion](https://crates.io/crates/criterion). Benchmarked are all 
ciphers - encryption and decryption aswell. For any benchmark a randomly generated string of 20000 characters 
is used. To benchmark just

```bash
cargo bench
```

# Playfair Cipher
Implementation of the [PlayFair cipher](https://en.wikipedia.org/wiki/Playfair_cipher) - nothing special, nothing useful, just for fun. 


## Encrypt

### Example 5 to 5

```rust
use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let pfc = PlayFairKey::new_5_to_5("playfair example");
match pfc.encrypt("hide the gold in the tree stump") {
  Ok(crypt) => {
    assert_eq!(crypt, "BMODZBXDNABEKUDMUIXMMOUVIF");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```
    
### Example 6 to 6

```rust
use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let pfc = PlayFairKey::new_6_to_6("play 3645 fair 8760 example");
match pfc.encrypt("hide the gold in the tree stump at 5 o'clock.") {
  Ok(crypt) => {
    assert_eq!(crypt, "SXG0SJGQW5H5OUGX2MXMXQUN733Q0WDPNDHB");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

### Example 5 to 5

```rust
use playfair_cipher::playfair::PlayFairKey as PlayFairKey;
use playfair_cipher::errors::CharNotInKeyError as CharNotInKeyError;
use playfair_cipher::cryptable::Cypher;

let pfc = PlayFairKey::new_5_to_5("playfair example");
match pfc.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF") {
  Ok(crypt) => {
    assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMP");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};    
```

### Example 6 to 6
```rust
use playfair_cipher::{playfair::PlayFairKey, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let pfc = PlayFairKey::new_6_to_6("play 3645 fair 8760 example");
match pfc.decrypt("SXG0SJGQW5H5OUGX2MXMXQUN733Q0WDPNDHB") {
  Ok(crypt) => {
    assert_eq!(crypt, "HIDETHEGOLDINTHETREXESTUMPAT5OCLOCKX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

# Two Square Cipher

Implementation of the [TwoSquare cipher](https://en.wikipedia.org/wiki/Two-square_cipher) - nothing special, nothing useful, just for fun.

## Encrypt
 
### Example 5 to 5

```rust
use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;;

let tsq = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
match tsq.encrypt("joe") {
  Ok(crypt) => {
    assert_eq!(crypt, "NYMT");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```
### Example 6 to 6

```rust
use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;;

let tsq = TwoSquare::new_6_to_6("EXAMPLE", "KEYWORD");
match tsq.encrypt("Ben Wade takes the 3:10 train to Yuma.") {
  Ok(crypt) => {
    assert_eq!(crypt, "CKNWEBMPEYAPRJLX01WYXJNTKOVLE0");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

### Example 5 to 5
 
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
### Example 6 to 6

```rust
use playfair_cipher::{two_square::TwoSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;;

let tsq = TwoSquare::new_6_to_6("EXAMPLE", "KEYWORD");
match tsq.decrypt("CKNWEBMPEYAPRJLX01WYXJNTKOVLE0") {
  Ok(crypt) => {
    assert_eq!(crypt, "BENWADETAKESTHE310TRAINTOYUMAX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

# Four Square Cipher
Implementation of the [FourSquare cipher](https://en.wikipedia.org/wiki/Four-square_cipher) - nothing special, nothing useful, just for fun.

## Encrypt

### Example 5 to 5
 
As described at <https://en.wikipedia.org/wiki/Four-square_cipher>

```rust
use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let fsq = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
match fsq.encrypt("joe") {
  Ok(crypt) => {
    assert_eq!(crypt, "DIAZ");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

### Example 6 to 6

```rust
use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let fsq = FourSquare::new_6_to_6("EXAMPLE", "KEYWORD");
match fsq.encrypt("Ben Wade takes the 3:10 train to Yuma.") {
  Ok(crypt) => {
    assert_eq!(crypt, "PEOQMKXUPDEUSAL201WIADJQI0RJLP");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```

## Decrypt

### Example 5 to 5
 

```rust
use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let fsq = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
match fsq.decrypt("DIAZ") {
  Ok(crypt) => {
    assert_eq!(crypt, "IOEX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```
### Example 6 to 6

```rust
use playfair_cipher::{four_square::FourSquare, errors::CharNotInKeyError};
use playfair_cipher::cryptable::Cypher;

let fsq = FourSquare::new_6_to_6("EXAMPLE", "KEYWORD");
match fsq.decrypt("PEOQMKXUPDEUSAL201WIADJQI0RJLP") {
  Ok(crypt) => {
    assert_eq!(crypt, "BENWADETAKESTHE310TRAINTOYUMAX");
  }
  Err(e) => panic!("CharNotInKeyError {}", e),
};
```


That's it.

