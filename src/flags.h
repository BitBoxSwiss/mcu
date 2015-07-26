/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


#ifndef _FLAGS_H_
#define _FLAGS_H_


#define _STRINGIFY(S) #S
#define STRINGIFY(S) _STRINGIFY(S)

#define GENERATE_STRING(STRING) #STRING,
#define GENERATE_ENUM_ATTR(ENUM) ATTR_ ## ENUM ## _,
#define GENERATE_ENUM_CMD(ENUM) CMD_ ## ENUM ## _,

#define FOREACH_CMD(CMD)        \
  /*    parent commands     */  \
  /*    requiring touch     */  \
        CMD(sign)               \
        CMD(seed)               \
        CMD(test)               \
        CMD(password)           \
        CMD(touchbutton)        \
  /* placeholder don't move */  \
        CMD(require_touch)      \
  /*    parent commands     */  \
  /*    not requiring touch */  \
        CMD(led)                \
        CMD(xpub)               \
        CMD(name)               \
        CMD(reset)              \
        CMD(device)             \
        CMD(random)             \
        CMD(backup)             \
        CMD(aes256cbc)          \
        CMD(verifypass)         \
        CMD(ciphertext)         \
  /*    child commands      */  \
        CMD(timeout)            \
        CMD(holdtime)           \
        CMD(threshold)          \
        CMD(generate)           \
        CMD(source)             \
        CMD(type)               \
        CMD(data)               \
        CMD(keypath)            \
        CMD(change_keypath)     \
        CMD(strength)           \
        CMD(salt)               \
        CMD(filename)           \
        CMD(decrypt)            \
        CMD(encrypt)            \
        CMD(pin)                \
  /* placeholder don't move */  \
        CMD(none)                /* keep last */

#define FOREACH_ATTR(ATTR)      \
  /*    command attributes  */  \
        ATTR(transaction)       \
        ATTR(hash)              \
        ATTR(true)              \
        ATTR(list)              \
        ATTR(lock)              \
        ATTR(erase)             \
        ATTR(toggle)            \
        ATTR(pseudo)            \
        ATTR(create)            \
        ATTR(export)            \
        ATTR(serial)            \
        ATTR(version)           \
        ATTR(decrypt)           \
        ATTR(encrypt)           \
        ATTR(password)          \
        ATTR(xpub)              \
        ATTR(__ERASE__)         \
        ATTR(__FORCE__)         \
        ATTR(none)               /* keep last */

enum CMD_ENUM { FOREACH_CMD(GENERATE_ENUM_CMD) };
enum ATTR_ENUM { FOREACH_ATTR(GENERATE_ENUM_ATTR) };

#define CMD_NUM      CMD_none_
#define ATTR_NUM     ATTR_none_


enum REPORT_FLAGS {
    SUCCESS, ERROR, ERROR_MEM,
    ECHO,
    SAME, DIFFERENT, NEXT,
    TOUCHED, NOT_TOUCHED,
    RESET,
    INITIALIZE, ITERATE,
    ERASED, NOT_ERASED,
    EMPTY
};


#define PASSWORD_LEN_MIN            4
#define DATA_LEN_MAX                1024/*base64 increases size by ~4/3; AES encryption by max 32 char*/

#define FLAG_ERR_PASSWORD_LEN       "The password length must be at least " STRINGIFY(PASSWORD_LEN_MIN) " characters."
#define FLAG_ERR_NO_PASSWORD        "Please set a password."
#define FLAG_ERR_NO_INPUT           "No input received."
#define FLAG_ERR_DATA_LEN           "Data must be less than " STRINGIFY(DATA_LEN_MAX)" characters."
#define FLAG_ERR_REPORT_BUFFER      "{\"output\":{\"error\":\"Output report buffer overflow.\"}}"
#define FLAG_ERR_JSON_PARSE         "JSON parse error."
#define FLAG_ERR_JSON_BRACKET       "Is the command enclosed by curly brackets?"
#define FLAG_ERR_INVALID_CMD        "Invalid command."
#define FLAG_ERR_MULTIPLE_CMD       "Only one command allowed at a time."
#define FLAG_ERR_RESET              "Too many failed access attempts. Device reset."
#define FLAG_ERR_RESET_WARNING      "Too many access errors will cause the device to reset."
#define FLAG_ERR_DEVICE_LOCKED      "Device locked. Erase device to access this command."
#define FLAG_ERR_BIP32_MISSING      "BIP32 mnemonic not present."
#define FLAG_ERR_DECRYPT            "Could not decrypt."
#define FLAG_ERR_MNEMO_CHECK        "Invalid mnemonic."
#define FLAG_ERR_SIGN_LEN           "Incorrect data length. A 32-byte hexadecimal value (64 characters) is expected."
#define FLAG_ERR_DESERIALIZE        "Could not deserialize outputs or wrong change keypath."
#define FLAG_ERR_KEY_GEN            "Could not generate key."
#define FLAG_ERR_SIGN               "Could not sign."
#define FLAG_ERR_SALT_LEN           "Salt must be less than " STRINGIFY(SALT_LEN_MAX) " characters."
#define FLAG_ERR_SEED_SD            "Seed creation requires an SD card for automatic encrypted backup of the seed."
#define FLAG_ERR_SEED_SD_NUM        "Too many backup files. Please remove one from the SD card."
#define FLAG_ERR_SEED_MEM           "Could not allocate memory for seed."
#define FLAG_ERR_ENCRYPT_MEM        "Could not encrypt."
#define FLAG_ERR_ATAES              "Chip communication error."
#define FLAG_ERR_FLASH              "Could not read flash."
#define FLAG_ERR_NO_MCU             "Ignored for non-embedded testing."
#define FLAG_ERR_SD_CARD            "Please insert SD card."
#define FLAG_ERR_SD_MOUNT           "Could not mount the SD card."
#define FLAG_ERR_SD_OPEN            "Could not open the file."
#define FLAG_ERR_SD_OPEN_DIR        "Could not open the directory."
#define FLAG_ERR_SD_FILE_CORRUPT    "Corrupted file."
#define FLAG_ERR_SD_WRITE           "Could not write the file."
#define FLAG_ERR_SD_WRITE_LEN       "Text to write is too large."
#define FLAG_ERR_SD_READ            "Could not read the file."
#define FLAG_ERR_SD_ERASE           "May not have erased all files (or no file present)."
#define FLAG_ERR_SD_FILE_EXISTS     "File exists."
#define FLAG_ERR_NUM_FILES          "Too many files to read. The list is truncated."
#define FLAG_ERR_PASSWORD_ID        "Invalid password ID."

#endif
