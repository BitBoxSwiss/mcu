Digital Bitbox Firmware
============

[![Build Status](https://travis-ci.org/digitalbitbox/mcu.svg?branch=master)](https://travis-ci.org/digitalbitbox/mcu)
[![Coverage Status](https://coveralls.io/repos/digitalbitbox/mcu/badge.svg?branch=master&service=github)](https://coveralls.io/github/digitalbitbox/mcu?branch=master)
[![License](http://img.shields.io/:License-MIT-yellow.svg)](LICENSE)

**MCU code for the [Digital Bitbox](https://digitalbitbox.com) hardware wallet.**

All communication to the hardware wallet enters and exits a single gateway `char *commander(const char *command)` that receives an encrypted command and returns an encrypted reply. The communication protocol is desribed in the [API](https://digitalbitbox.com/api.html). 

See the `tests_cmdline.c` code for a simple example and the `tests_api.c` code to test the API. The tests can be compiled and run locally without the need for a device. The `tests_api.c` code will also test a live device if one is plugged into a USB slot. This requires installation of the [hidapi library](http://www.signal11.us/oss/hidapi/) for USB communication, a micro SD card in the device, and a number of touch button presses (to permit `erase` and `sign` commands).  

ECDSA signatures are performed using a simplified version of the [micro ECC library](https://github.com/kmackay/micro-ecc). The micro ECC library is designed for microcontrollers, resistant to known side channel attacks, and does not use dynamic memory allocation. In the simplified version, non-secp256k1 ECDSA curves were removed and RFC6979 (deterministic k) and convenience functions were added.

**Standardized functions:**

	Cryptographic: secp256k1, AES-256-CBC, SHA2, HMAC, PBKDF2, RIPEMD160
	Encoding: Base-64, Base-58-check, JSON
	Bitcoin: BIP32, BIP39, BIP44



## Build Instructions
Dependencies:

- https://github.com/signal11/hidapi
- Doxygen (Optional, to generate source code documentation)
- Graphviz (Optional, to generate graphs for the Doxygen documentation)

OSX:

    brew install hidapi
    brew install doxygen graphviz
--------------

Basic build steps:

    mkdir build
    cd build
    cmake ..
    make
    make doc # optional


## Contributing
Please do *NOT* use an editor that automatically reformats.

Use the coding style set by astyle (http://astyle.sourceforge.net/) with the following parameteres:

    astyle --style=stroustrup --indent-switches --indent-labels --pad-oper --pad-header --align-pointer=name --add-brackets --convert-tabs --max-code-length=90 --break-after-logical --suffix=none *.c *.h --recursive --exclude=src/yajl --exclude=src/secp256k1 --exclude=tests/windows/hidapi

All commits have to be signed with PGP.
Set Git to auto-sign your commits:

    git config --global user.signingkey YourGPGKeyID
    git config --global commit.gpgsign true

The PGP public keys of the contributors can be found in contrib/contributors_gpg_keys. Please add your PGP key with your first pull request.


#### astyle Git hook

For convenience, enable a Git hook to trigger the `astyle` styling whenever a `git commit` operation is performed. This is done by typing in the repository directory:

    cd .git/hooks
    ln -s ../../contrib/git/pre-commit

