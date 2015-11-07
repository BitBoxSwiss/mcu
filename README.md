Digital Bitbox Firmware
============

[![Build Status](https://travis-ci.org/digitalbitbox/mcu.svg?branch=master)](https://travis-ci.org/digitalbitbox/mcu)
[![Coverage Status](https://coveralls.io/repos/digitalbitbox/mcu/badge.svg?branch=master&service=github)](https://coveralls.io/github/digitalbitbox/mcu?branch=master)
[![License](http://img.shields.io/:License-MIT-yellow.svg)](LICENSE)

**MCU code for the [Digital Bitbox](https://digitalbitbox.com) hardware wallet.**

All communication to the hardware wallet enters and exits a single gateway `char *commander(const char *command)` that receives an encrypted command and returns an encrypted reply. The communication protocol is described in the [API](https://digitalbitbox.com/api.html). 

The code can be compiled and tested locally without the need for a device. See the `tests_cmdline.c` code for a simple example and the `tests_api.c` code to test the full API. The `tests_api.c` code will also test a live device if one is plugged into a USB slot. This requires installation of the [hidapi library](http://www.signal11.us/oss/hidapi/) for USB communication, a micro SD card in the device, and a number of touch button presses to permit `erase` and `sign` commands. WARNING: data on the device and micro SD card will be **lost** when running `tests_api.c`.

ECDSA signatures are performed with either the [bitcoin core secp256k1 library](https://github.com/bitcoin/secp256k1) or using a simplified version of the smaller [micro ECC library](https://github.com/kmackay/micro-ecc), depending on a setting in the `CMakeLists.txt` file. Each library is resistant to known side channel attacks.


**Standardized functions:**

	Cryptographic: secp256k1, RFC6979, AES-256-CBC, SHA2, HMAC, PBKDF2, RIPEMD160
	Encoding: Base-64, Base-58-check, JSON
	Bitcoin: BIP32, BIP39, BIP44



## Build Instructions
Dependencies:

- [HIDAPI](https://github.com/signal11/hidapi)
- [GCC ARM cross compiler](https://launchpad.net/gcc-arm-embedded/+download) (Optional, to build the firmware binary)
- Doxygen (Optional, to generate source code documentation)
- Graphviz (Optional, to generate graphs for the Doxygen documentation)

For OSX:

    brew install hidapi
    brew install doxygen graphviz
--------------

Building code for tests:

    git clone https://github.com/digitalbitbox/mcu
    mkdir build
    cd build
    cmake .. -DBUILD_TYPE=test
    make
    make test # optional

Building firmware:

    git clone https://github.com/digitalbitbox/mcu
    mkdir build
    cd build
    cmake .. -DBUILD_TYPE=firmware
    make


## Contributing
Please do not use an editor that automatically reformats.

Please do use the coding style set by astyle (http://astyle.sourceforge.net/) with the following parameters:

    astyle --style=stroustrup --indent-switches --indent-labels --pad-oper --pad-header --align-pointer=name --add-brackets --convert-tabs --max-code-length=90 --break-after-logical --suffix=none *.c *.h --recursive --exclude=src/yajl --exclude=src/secp256k1 --exclude=src/drivers --exclude=tests/windows/hidapi | grep Formatted

Pull requests will automatically fail if the coding style is not met. For convenience, enable a Git hook to trigger the `astyle` styling whenever a `git commit` operation is performed. This is done by typing in the repository directory:

    cd .git/hooks
    ln -s ../../contrib/git/pre-commit


All commits must be signed with PGP. To set Git to auto-sign your commits:

    git config --global user.signingkey YourGPGKeyID
    git config --global commit.gpgsign true

The PGP public keys of the contributors can be found in contrib/contributors_gpg_keys. Please add your PGP key with your first pull request.


