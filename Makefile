CC     = gcc
CFLAGS = -g -Os # optimized compile
CFLAGS += -W -Wall -Wextra -Wimplicit-function-declaration -Wredundant-decls -Wstrict-prototypes -Wundef -Wshadow -Wpointer-arith -Wformat -Wreturn-type -Wsign-compare -Wmultichar -Wformat-nonliteral -Winit-self -Wuninitialized -Wformat-security -Werror 
CFLAGS += -std=c99


#CFLAGS = -g -O0 # valgrind compile

# disable deprecated warnings for openssl on mac
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -D TESTING

LIBOPENSSL = -lcrypto

ifdef TRAVIS_BUILD
CFLAGS += -D TRAVIS_BUILD
else
LIBHIDAPI = -lhidapi
endif

CFLAGS += -Isrc
OBJS =  src/wallet.o src/sha2.o src/random.o src/hmac.o src/bip32.o src/pbkdf2.o src/utils.o src/aes.o src/base64.o src/jsmn.o src/commander.o src/led.o src/memory.o src/base58.o src/ripemd160.o src/sham.o src/uECC.o

%.o: %.c ;  $(CC) $(CFLAGS) -c -o $@ $<


all: tests_cmdline tests_unit tests_openssl 
api: tests_api

tests: tests.o $(OBJS) ; $(CC) tests.o $(OBJS) -o tests
tests_api: tests_api.o $(OBJS) ; $(CC) tests_api.o $(OBJS) $(LIBHIDAPI) -o tests_api
tests_unit: tests_unit.o $(OBJS) ; $(CC) tests_unit.o $(OBJS) -o tests_unit
tests_cmdline: tests_cmdline.o $(OBJS) ; $(CC) tests_cmdline.o $(OBJS) -o tests_cmdline
tests_openssl: tests_openssl.o $(OBJS) ; $(CC) tests_openssl.o $(OBJS) $(LIBOPENSSL) -o tests_openssl


clean: ; rm -f *.o tests tests_cmdline tests_unit tests_openssl tests_api
