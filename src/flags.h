/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum

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


#define COMMANDER_REPORT_SIZE       3584
#define COMMANDER_NUM_SIG_MIN       14// Must be >= desktop app's `MAX_INPUTS_PER_SIGN` !!
#define COMMANDER_SIG_LEN           154// sig + recid + json formatting
#define COMMANDER_ARRAY_MAX         (COMMANDER_REPORT_SIZE - (COMMANDER_SIG_LEN * 8))// Multiple is emperically found such that NUM_SIG_MIN is maximum
#define COMMANDER_ARRAY_ELEMENT_MAX 1024
#define COMMANDER_MAX_ATTEMPTS      15// max PASSWORD or LOCK PIN attempts before device reset
#define COMMANDER_TOUCH_ATTEMPTS    10// number of attempts until touch button hold required to login
#define VERIFYPASS_FILENAME         "verification.pdf"
#define VERIFYPASS_CRYPT_TEST       "Digital Bitbox 2FA"
#define VERIFYPASS_LOCK_CODE_LEN    16// bytes
#define DEVICE_DEFAULT_NAME         "My Digital Bitbox"
#define SD_FILEBUF_LEN_MAX          (COMMANDER_REPORT_SIZE * 4 / 7)
#define AES_DATA_LEN_MAX            (COMMANDER_REPORT_SIZE * 4 / 7)// base64 increases size by ~4/3; AES encryption by max 32 char
#define PASSWORD_LEN_MIN            4


#define _STRINGIFY(S) #S
#define STRINGIFY(S) _STRINGIFY(S)


// Command keys
#define CMD_TABLE \
/* parent keys  */\
/*  with touch  */\
X(sign)           \
X(seed)           \
X(reset)          \
X(password)       \
X(bootloader)     \
X(hidden_password)\
X(REQUIRE_TOUCH)   /* placeholder - do not move */\
/* parent keys  */\
/*  w/o touch   */\
X(verifypass)     \
X(led)            \
X(xpub)           \
X(name)           \
X(ecdh)           \
X(device)         \
X(random)         \
X(backup)         \
X(ping)           \
X(feature_set)    \
/*  child keys  */\
X(source)         \
X(entropy)        \
X(raw)            \
X(type)           \
X(hash)           \
X(data)           \
X(meta)           \
X(pubkey)         \
X(checkpub)       \
X(filename)       \
X(keypath)        \
X(present)        \
X(decrypt)        \
X(encrypt)        \
X(script)         \
X(value)          \
X(erase)          \
X(check)          \
X(key)            \
X(sig)            \
X(recid)          \
X(pin)            \
X(U2F)            \
X(U2F_hijack)     \
X(U2F_counter)    \
/*  reply keys  */\
X(ciphertext)     \
X(echo)           \
X(TFA)            \
X(sham)           \
X(input)          \
X(ataes)          \
X(touchbutton)    \
X(warning)        \
X(NUM)             /* keep last */


// Attributes
#define ATTR_TABLE \
X(success)        \
X(error)          \
X(accept)         \
X(aborted)        \
X(meta)           \
X(list)           \
X(sdcard)         \
X(lock)           \
X(bootlock)       \
X(unlock)         \
X(decrypt)        \
X(encrypt)        \
X(verify)         \
X(true)           \
X(false)          \
X(erase)          \
X(abort)          \
X(blink)          \
X(pseudo)         \
X(create)         \
X(backup)         \
X(export)         \
X(xpub)           \
X(id)             \
X(name)           \
X(info)           \
X(seeded)         \
X(serial)         \
X(version)        \
X(password)       \
X(TFA)            \
X(all)            \
X(HWW)            \
X(U2F)            \
X(U2F_load)       \
X(U2F_create)     \
X(U2F_hijack)     \
X(__ERASE__)      \
X(__FORCE__)      \
X(NUM)             /* keep last */


// Status and error flags
#define FLAG_TABLE \
X(OK,                    0, 0)\
X(ERROR,                 0, 0)\
X(ERROR_MEM,             0, 0)\
X(TOUCHED,               0, 0)\
X(NOT_TOUCHED,           0, 0)\
X(TOUCHED_ABORT,         0, 0)\
X(TOUCH_SHORT,           0, 0) /* brief touch accept; hold 3s reject       */\
X(TOUCH_LONG,            0, 0) /* brief touch reject; hold 3s accept (led) */\
X(TOUCH_LONG_BLINK,      0, 0) /* brief touch reject; hold 3s accept (led) */\
X(TOUCH_TIMEOUT,         0, 0) /* touch accept; 3s timeout reject          */\
X(TOUCH_REJECT_TIMEOUT,  0, 0) /* touch reject; 3s timeout accept          */\
X(KEY_PRESENT,           0, 0)\
X(KEY_ABSENT,            0, 0)\
X(RESET,                 0, 0)\
X(ACCESS_INITIALIZE,     0, 0)\
X(ACCESS_ITERATE,        0, 0)\
X(MEM_ERASED,            0, 0)\
X(MEM_NOT_ERASED,        0, 0)\
X(SD_REPLACE,            0, 0)\
X(SD_NO_REPLACE,         0, 0)\
X(JSON_STRING,           0, 0)\
X(JSON_BOOL,             0, 0)\
X(JSON_ARRAY,            0, 0)\
X(JSON_NUMBER,           0, 0)\
X(JSON_NONE,             0, 0)\
/* placeholder don't move  */ \
X(FLAG_ERROR_START,      0, 0)\
/* error flags             */ \
X(ERR_IO_NO_PASSWORD,  101, "Please set a password.")\
X(ERR_IO_PASSWORD_LEN, 102, "The password length must be at least " STRINGIFY(PASSWORD_LEN_MIN) " characters.")\
X(ERR_IO_NO_INPUT,     103, "No input received.")\
X(ERR_IO_INVALID_CMD,  104, "Invalid command.")\
X(ERR_IO_MULT_CMD,     105, "Only one command allowed at a time.")\
X(ERR_IO_DATA_LEN,     106, "Data must be less than " STRINGIFY(AES_DATA_LEN_MAX)" characters.")\
X(ERR_IO_REPORT_BUF,   107, "Output buffer overflow.")\
X(ERR_IO_DECRYPT,      108, "Could not decrypt.")\
X(ERR_IO_JSON_PARSE,   109, "JSON parse error.")\
X(ERR_IO_RESET,        110, "Too many failed access attempts. Device reset.")\
X(ERR_IO_LOCKED,       111, "Device locked. Erase device to access this command.")\
X(ERR_IO_PW_COLLIDE,   112, "Device password matches reset password. Disabling reset password.")\
X(ERR_IO_TOUCH_BUTTON, 113, "Due to many login attempts, the next login requires holding the touch button for 3 seconds.")\
X(ERR_SEED_SD,         200, "Seed creation requires an SD card for automatic encrypted backup of the seed.")\
X(ERR_SEED_SD_NUM,     201, "Too many backup files. Please remove one from the SD card.")\
X(ERR_SEED_MEM,        202, "Could not allocate memory for seed.")\
X(ERR_SEED_INVALID,    204, "Invalid seed.")\
X(ERR_KEY_MASTER,      250, "Master key not present.")\
X(ERR_KEY_CHILD,       251, "Could not generate key.")\
X(ERR_KEY_ECDH,        252, "Could not generate ECDH secret.")\
X(ERR_KEY_ECDH_LEN,    253, "Incorrect serialized pubkey length. A 33-byte hexadecimal value (66 characters) is expected.")\
X(ERR_SIGN_PUBKEY_LEN, 300, "Incorrect pubkey length. A 33-byte hexadecimal value (66 characters) is expected.")\
X(ERR_SIGN_HASH_LEN,   301, "Incorrect hash length. A 32-byte hexadecimal value (64 characters) is expected.")\
X(ERR_SIGN_DESERIAL,   302, "Could not deserialize outputs or wrong change keypath.")\
X(ERR_SIGN_ECCLIB,     303, "Could not sign.")\
X(ERR_SIGN_TFA_PIN,    304, "Incorrect TFA pin.")\
X(ERR_SD_CARD,         400, "Please insert SD card.")\
X(ERR_SD_MOUNT,        401, "Could not mount the SD card.")\
X(ERR_SD_OPEN_FILE,    402, "Could not open a file to write - it may already exist.")\
X(ERR_SD_OPEN_DIR,     403, "Could not open the directory.")\
X(ERR_SD_CORRUPT_FILE, 404, "Corrupted file.")\
X(ERR_SD_WRITE_FILE,   405, "Could not write the file.")\
X(ERR_SD_WRITE_LEN,    406, "Text to write is too large.")\
X(ERR_SD_READ_FILE,    407, "Could not read the file.")\
X(ERR_SD_ERASE,        408, "May not have erased all files (or no file present).")\
X(ERR_SD_NUM_FILES,    409, "Too many files to read. The list is truncated.")\
X(ERR_SD_NO_MATCH,     410, "Backup file does not match wallet.")\
X(ERR_SD_BAD_CHAR,     411, "Filenames limited to alphanumeric values, hyphens, and underscores.")\
X(ERR_SD_KEY,          412, "Please provide an encryption key.")\
X(ERR_MEM_ATAES,       500, "Chip communication error.")\
X(ERR_MEM_FLASH,       501, "Could not read flash.")\
X(ERR_MEM_ENCRYPT,     502, "Could not encrypt.")\
X(ERR_MEM_SETUP,       503, "Device initialization in progress.")\
X(ERR_TOUCH_ABORT,     600, "Aborted by user.")\
X(ERR_TOUCH_TIMEOUT,   601, "Touchbutton timed out.")\
X(WARN_RESET,          900, "attempts remain before the device is reset.")\
X(WARN_NO_MCU,         901, "Ignored for non-embedded testing.")\
X(WARN_SD_NUM_FILES,   902, "Too many backup files to read. The list is truncated.")\
X(WARN_RESET_TOUCH,    903, "attempts remain before the device is reset. The next login requires holding the touch button.")\
X(FLAG_NUM,              0, 0)/* keep last */


#define X(a) CMD_ ## a,
enum CMD_ENUM { CMD_TABLE };
#undef X

#define X(a) ATTR_ ## a,
enum CMD_ATTR_ENUM { ATTR_TABLE };
#undef X

#define X(a, b, c) DBB_ ## a,
enum FLAG_ENUM { FLAG_TABLE };
#undef X


const char *cmd_str(int cmd);
const char *attr_str(int attr);
const char *flag_code(int flag);
const char *flag_msg(int flag);


#endif
