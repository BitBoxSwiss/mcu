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
)

set(C-HW-SOURCES
    ataes132.c
    sd.c
    systick.c
    touch.c
)


set(YAJL-SOURCES
    yajl/yajl.c
    yajl/yajl_lex.c
    yajl/yajl_parser.c
    yajl/yajl_buf.c
    yajl/yajl_encode.c
    yajl/yajl_gen.c
    yajl/yajl_alloc.c
    yajl/yajl_tree.c
    yajl/yajl_version.c
)

include_directories(SYSTEM)

add_library(bitbox
  SHARED
  ${C-SOURCES}
  #${C-HW-SOURCES}
  ${YAJL-SOURCES}
)
