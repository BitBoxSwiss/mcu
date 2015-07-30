set(C-SOURCES
    aes.c
    base58.c
    base64.c
    bip32.c
    commander.c
    hmac.c
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
    version.c
)

set(C-HW-SOURCES
    ataes132.c
    sd.c
    systick.c
    touch.c
)


set(YAJL-SOURCES
    yajl/src/yajl.c
    yajl/src/yajl_lex.c
    yajl/src/yajl_parser.c
    yajl/src/yajl_buf.c
    yajl/src/yajl_encode.c
    yajl/src/yajl_gen.c
    yajl/src/yajl_alloc.c
    yajl/src/yajl_tree.c
    yajl/src/yajl_version.c
)

include_directories(SYSTEM)

add_library(bitbox
  SHARED
  ${C-SOURCES}
  #${C-HW-SOURCES}
  ${YAJL-SOURCES}
)
