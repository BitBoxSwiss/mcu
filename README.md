<img src="./doc/BB01_logo_github.svg" width="345px"/>

[![Build Status](https://travis-ci.org/digitalbitbox/mcu.svg?branch=master)](https://travis-ci.org/digitalbitbox/mcu)
[![Coverage Status](https://coveralls.io/repos/github/digitalbitbox/mcu/badge.svg?branch=master)](https://coveralls.io/github/digitalbitbox/mcu?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7041/badge.svg)](https://scan.coverity.com/projects/mcu)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)]()


The [Bitbox01](https://shiftcrypto.com) is a hardware wallet that simplifies secure handling of crypto coins through storing private keys and signing transactions. The content of this repository is the bootloader and firmware used on the device. The BitBox01 is meant to be used primarily with the [BitBox App](https://github.com/digitalbitbox/bitbox-wallet-app), although third party integration is possible through the BitBox01 API.

The main functionality of the firmware is the following:

* Safely receive and send coins
* Back up the seed to a microSD card
* Generate a random seed from multiple strong sources of entropy
* Protect the seed from attackers
* Derive keys from the seed according to BIP39 and BIP32
* Return the extended public key for a keypath so that the app can find all unspent transaction outputs
* Second factor authentication (FIDO U2F compliant)


## Building the code

All communication to the hardware wallet enters and exits a single gateway `char *commander(const char *command)` that receives an encrypted command and returns an encrypted reply. The communication protocol is described in the [API](https://digitalbitbox.com/api.html). A Python script to interact with the device is in the `py/` folder.

The code can be compiled and tested locally without the need for a device, e.g., `tests/tests_api.c` tests the full API. The `tests_api.c` code will also test a live device if one is plugged into a USB slot. This requires installation of the [hidapi library](http://www.signal11.us/oss/hidapi/) for USB communication, a micro SD card in the device, and a number of touch button presses to permit `erase` and `sign` commands.

ECDSA signatures are performed with either the [bitcoin core secp256k1 library](https://github.com/bitcoin/secp256k1) or using a simplified version of the smaller [micro ECC library](https://github.com/kmackay/micro-ecc), depending on a setting in the `CMakeLists.txt` file. Each library is resistant to known side channel attacks.


#### Build instructions

Dependencies:

- [GNU ARM Embedded Toolchain](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads)
- [HIDAPI](https://github.com/signal11/hidapi) (For live testing)
- cmake
- Doxygen (Optional, to generate source code documentation)
- Graphviz (Optional, to generate graphs for the Doxygen documentation)

Build:

    git clone https://github.com/digitalbitbox/mcu && cd mcu
    make test  #  or `make firmware` or `make bootloader`
    make run-test

Load the firmware by the bootloader (requires a bootloader already on the device):

- If you used the device with the desktop app, your bootloader will be locked
    - Unlock it by sending the `message = '{"bootloader":"unlock"}'` command with `send_command.py` ([see python API documentation](https://github.com/shiftdevices/mcu/tree/master/py))
    - Long touch the device when the LED turns on
    - You should receive a `Reply:   {"bootloader":"unlock"}` reply
- Long touch the device after plugging in to enter the bootloader
- Flash the new firmware with `./load_firmware.py ../build/bin/firmware.bin debug` from the `py` directory

#### Deterministic builds

See the [releases page](releases) for instructions or to download deterministically built firmware.

## Contributing

Please use the coding style set by AStyle version 3.0 (http://astyle.sourceforge.net/; also available from homebrew) with the following parameters:

    astyle --style=kr --indent-switches --indent-labels --pad-oper --pad-header --align-pointer=name --add-braces --convert-tabs --max-code-length=90 --break-after-logical --suffix=none *.c *.h --recursive --exclude=src/yajl --exclude=src/secp256k1 --exclude=src/drivers --exclude=tests/hidapi | grep Formatted

Pull requests will automatically fail if the coding style is not met. For convenience, enable a Git hook to trigger the `astyle` styling whenever a `git commit` operation is performed. This is done by typing in the repository directory:

    cd .git/hooks
    ln -s ../../contrib/git/pre-commit


All commits must be signed with PGP. To set Git to auto-sign your commits:

    git config --global user.signingkey YourGPGKeyID
    git config --global commit.gpgsign true

The PGP public keys of the contributors can be found in contrib/contributors_gpg_keys. Please add your PGP key with your first pull request.

## Reporting a Vulnerability

See our [security policy](SECURITY.md).
