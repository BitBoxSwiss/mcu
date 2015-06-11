[![Build Status](https://travis-ci.org/digitalbitbox/mcu.svg?branch=master)](https://travis-ci.org/digitalbitbox/mcu)


MCU code for the [Digital Bitbox](https://digitalbitbox.com) hardware wallet.

All communication to the hardware wallet enters and exits a single gateway `char *commander(const char *command)` that receives an encrypted command and returns an encrypted reply. The communication protocol is desribed in the [API](https://digitalbitbox.com/api.html). The code will compile on a computer by typing `make` - see the `tests_cmdline.c` code for a simple example and the `tests_api.c` code to test the API.

ECDSA signatures are performed using a simplified version of the [micro ECC library](https://github.com/kmackay/micro-ecc). The micro ECC library is designed for microcontrollers, resistant to known side channel attacks, and does not use dynamic memory allocation. In the simplified version, non-secp256k1 ECDSA curves were removed and RFC6979 (deterministic k) and convenience functions were added.

Standardized functions:

Cryptographic: secp256k1, AES-256-CBC, SHA2, HMAC, PBKDF2, RIPEMD160.
Encoding: Base-64, Base-58-check. 
Bitcoin: BIP32, BIP39, BIP44.
Other: JSMN (minimal JSON).
