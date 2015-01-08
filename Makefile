OUT    = tests
CC     = gcc
CFLAGS = -Os # optimized compile
CFLAGS += -W -Wall -Wextra -Wimplicit-function-declaration -Wredundant-decls -Wstrict-prototypes -Wundef -Wshadow -Wpointer-arith -Wformat -Wreturn-type -Wsign-compare -Wmultichar -Wformat-nonliteral -Winit-self -Wuninitialized -Wformat-security -Werror
#CFLAGS = -g -O0 # valgrind compile
CFLAGS += -D NOT_EMBEDDED


OBJS =  keys.o bignum.o ecdsa.o secp256k1.o sha2.o random.o hmac.o bip32.o ripemd160.o pbkdf2.o utils.o aes.o base64.o bip39.o jsmn.o commander.o led.o memory.o touch.o sd.o base58.o message.o

%.o: %.c ;  $(CC) $(CFLAGS) -c -o $@ $<

all: $(OUT)

$(OUT): $(OBJS) ; $(CC) $(OUT).c -o $@ $^ $(CFLAGS) 

clean: ; rm -rf *.o $(OUT)
