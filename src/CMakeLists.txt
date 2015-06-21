set(C-SOURCES
    aes.c
    base58.c
    base64.c
    bip32.c
    commander.c
    hmac.c
    jsmn.c
    led.c
    memory.c
    pbkdf2.c
    random.c
    ripemd160.c
    sha2.c
    sham.c
    uECC.c
    utils.c
    wallet.c
)

set(C-HW-SOURCES
    ataes132.c
    sd.c
    systick.c
    touch.c
)

include_directories(SYSTEM)

add_library(bitbox
  SHARED
  ${C-SOURCES}
  #${C-HW-SOURCES}
)
