#!/bin/bash

err_report() {
    printf "\n** ERROR on line $1 due to OpenSSL bug.\n** Remove 'dbbdev.key' and run the script again.\n\n"
    exit
}

trap 'err_report $LINENO' ERR


cat > u2f_keys.h <<EOF
#ifndef __U2F_KEYS_H_INCLUDED__
#define __U2F_KEYS_H_INCLUDED__

#include <stdint.h>

const uint8_t U2F_ATT_PRIV_KEY[] = {
EOF

if [ \! -e dbbdev.key ]; then
    openssl ecparam -genkey -out dbbdev.key -name prime256v1
fi

# This command sometimes appends 0x00 to the private key, 
# giving an incorrect length of 33 bytes.
# The script will abort if this occurs. Just rerun.
openssl ec -in dbbdev.key -text  |
    perl -e '$key = "\t"; while (<>) {
      if (/priv:/) { $priv = 1 }
      elsif (/pub:/) { $priv = 0 }
      elsif ($priv) {
        while ($_ =~ s/.*?([0-9a-f]{2})//) {
          $key .= "0x$1,";
          if ($num++ % 8 == 7) { $key .= "\n\t"; }
          else {$key .= " ";}
          if ($num == 33) { exit 1;}
        }
      }
    }
    $key =~ s/,\s*$/\n/s;
    print $key;' >> u2f_keys.h

cat >> u2f_keys.h <<EOF
};

const uint8_t U2F_ATT_CERT[] = {
EOF
    

openssl req -new -key dbbdev.key -out dbbdev.csr -subj "/CN=Digital Bitbox U2F"
openssl x509 -req -in dbbdev.csr -signkey dbbdev.key -days 7300 -out dbbdev.crt
openssl x509 -in dbbdev.crt -outform der | od -tx1 -Anone | perl -pe 's/  / /g;s/ ([0-9a-f]{2})/ 0x$1,/g; $_ =~ s/^s+/    /;' >> u2f_keys.h

cat >> u2f_keys.h <<EOF
};

#endif // __U2F_KEYS_H_INCLUDED__
EOF

if openssl verify -verbose -CAfile dbbdev.crt dbbdev.crt | grep -v "dbbdev.crt: OK"; then printf "\n\nERROR: Bad certificate.\n\n"; fi; 
rm dbbdev.key dbbdev.csr dbbdev.crt
