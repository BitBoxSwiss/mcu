Digital Bitbox Firmware
============

[![Build Status](https://travis-ci.org/digitalbitbox/mcu.svg?branch=master)](https://travis-ci.org/digitalbitbox/mcu)
[![Coverage Status](https://coveralls.io/repos/github/digitalbitbox/mcu/badge.svg?branch=master)](https://coveralls.io/github/digitalbitbox/mcu?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7041/badge.svg)](https://scan.coverity.com/projects/mcu)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)]()


**MCU code for the [Digital Bitbox](https://digitalbitbox.com) hardware wallet.**

All communication to the hardware wallet enters and exits a single gateway `char *commander(const char *command)` that receives an encrypted command and returns an encrypted reply. The communication protocol is described in the [API](https://digitalbitbox.com/api.html).

The code can be compiled and tested locally without the need for a device. See the `tests_cmdline.c` code for a simple example and the `tests_api.c` code to test the full API. The `tests_api.c` code will also test a live device if one is plugged into a USB slot. This requires installation of the [hidapi library](http://www.signal11.us/oss/hidapi/) for USB communication, a micro SD card in the device, and a number of touch button presses to permit `erase` and `sign` commands. WARNING: data on the device and micro SD card will be **lost** when running `tests_api.c`.

ECDSA signatures are performed with either the [bitcoin core secp256k1 library](https://github.com/bitcoin/secp256k1) or using a simplified version of the smaller [micro ECC library](https://github.com/kmackay/micro-ecc), depending on a setting in the `CMakeLists.txt` file. Each library is resistant to known side channel attacks.


**Standardized functions:**

	Cryptographic: secp256k1, RFC6979, AES-256-CBC, SHA2, HMAC, PBKDF2, RIPEMD160
	Encoding: Base-64, Base-58-check, JSON
	Bitcoin: BIP32, BIP39, BIP44



## Build Instructions

#### Building test code:

Dependencies:

- [HIDAPI](https://github.com/signal11/hidapi) (For live testing)
- Doxygen (Optional, to generate source code documentation)
- Graphviz (Optional, to generate graphs for the Doxygen documentation)

Build:

    git clone https://github.com/digitalbitbox/mcu && cd mcu
    mkdir build && cd build
    cmake .. -DBUILD_TYPE=test # `-DBUILD_TYPE=firmware` and `-DBUILD_TYPE=bootloader` work if a GNU ARM toolchain is installed
    make
    make test

#### Deterministic build of firmware:

Requires:

- [Vagrant](http://www.vagrantup.com/downloads)
- [Virtual Box](https://www.virtualbox.org/wiki/Downloads)

Build:

    git clone https://github.com/digitalbitbox/mcu && cd mcu
    vagrant up # Creates: build-vagrant/bin/firmware.bin
    vagrant halt
    

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
