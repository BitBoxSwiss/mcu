#!/bin/bash
set -e

cat > u2f_keys.h <<EOF
#ifndef __U2F_KEYS_H_INCLUDED__
#define __U2F_KEYS_H_INCLUDED__

#include <stdint.h>

const uint8_t U2F_ATT_PRIV_KEY[] = {
EOF

if [ \! -e dbbdev.key ]; then
    openssl ecparam -genkey -out dbbdev.key -name prime256v1
fi
openssl ec -in dbbdev.key -text  |
    perl -e '$key = "\t"; while (<>) {
      if (/priv:/) { $priv = 1 }
      elsif (/pub:/) { $priv = 0 }
      elsif ($priv) {
        while ($_ =~ s/.*?([0-9a-f]{2})//) {
          $key .= "0x$1,";
          if ($num++ % 8 == 7) { $key .= "\n\t"; }
          else {$key .= " ";}
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
openssl x509 -req -in dbbdev.csr -signkey dbbdev.key -days 3650 -out dbbdev.crt
openssl x509 -in dbbdev.crt -outform der | od -tx1 -Anone | perl -pe 's/  / /g;s/ ([0-9a-f]{2})/ 0x$1,/g; $_ =~ s/^s+/    /;' >> u2f_keys.h

cat >> u2f_keys.h <<EOF
};

#endif // __U2F_KEYS_H_INCLUDED__
EOF

rm dbbdev.key dbbdev.csr dbbdev.crt
