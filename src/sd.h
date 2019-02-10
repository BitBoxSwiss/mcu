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


#ifndef _SD_H_
#define _SD_H_


#include <stdint.h>


#define SD_PDF_DELIM         '-'
#define SD_PDF_DELIM_S       "-"
#define SD_PDF_DELIM2        '='
#define SD_PDF_DELIM2_S      "="
#define SD_PDF_LINE_BUF_SIZE 128
#define SD_PDF_HEAD "%%PDF-1.1\n"//%%\xDB\xDC\xDD\xDE\xDF\n"// uncomment the high-bit ascii characters if storing binary data
#define SD_PDF_1_0  "1 0 obj\n<</Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n"
#define SD_PDF_2_0  "2 0 obj\n<</Type /Pages\n/Kids [3 0 R]\n/Count 1\n/MediaBox [0 0 595 842]\n>>\nendobj\n"
#define SD_PDF_3_0  "3 0 obj\n<</Type /Page\n/Parent 2 0 R\n/Resources\n<</Font\n<</F1\n<</Type /Font\n/BaseFont /Helvetica\n/Subtype /Type1\n>>\n>>\n>>\n/Contents 4 0 R\n>>\nendobj\n"
#define SD_PDF_4_0_HEAD   "4 0 obj\n<< /Length %i >>\nstream\n"
#define SD_PDF_TEXT_BEGIN "BT\n/F1 12 Tf\n50 700 Td\n"
#define SD_PDF_TEXT_NAME  "(Wallet name: "
#define SD_PDF_TEXT_HWW   ") Tj\n0 -48 Td\n(Wallet backup:) Tj\n0 -24 Td\n("
#define SD_PDF_TEXT_U2F   ") Tj\n0 -48 Td\n(U2F backup:) Tj\n0 -24 Td\n("
#define SD_PDF_TEXT_FOOT  ") Tj\n0 -48 Td\n(Passphrase:  ______________________) Tj\n/F1 10 Tf\n0 -96 Td\n(For instructions, see digitalbitbox.com/backup.) Tj\n"
#define SD_PDF_TEXT_CONT  ") Tj\n0 -16 Td\n("
#define SD_PDF_BACKUP_START     "<20 2020202020> Tj\n"
#define SD_PDF_COMMENT_HEAD     "%%("
#define SD_PDF_COMMENT_CLOSE    ") Tj\n"
#define SD_PDF_COMMENT_CONT     SD_PDF_COMMENT_CLOSE SD_PDF_COMMENT_HEAD
#define SD_PDF_BACKUP_END       "<2020202020 20> Tj\n"
#define SD_PDF_REDUNDANCY_START "%%(REDUNDANCY_START) Tj\n"
#define SD_PDF_REDUNDANCY_END   "%%(REDUNCANCY_END) Tj\n"
#define SD_PDF_TEXT_END   "\nET\n"
#define SD_PDF_4_0_END    "endstream\nendobj\n"
#define SD_PDF_END        "xref\n0 5\n0000000000 65535 f \n%010i 00000 n \n%010i 00000 n \n%010i 00000 n \n%010i 00000 n \ntrailer\n<<\n/Size 5\n/Root 1 0 R\n>>\nstartxref\n%i\n"
#define SD_PDF_EOF        "%%%%EOF"


uint8_t sd_list(int cmd);
uint8_t sd_card_inserted(void);
uint8_t sd_file_exists(const char *fn);
uint8_t sd_erase(int cmd, const char *fn);
char *sd_load(const char *fn, int cmd);
uint8_t sd_write(const char *fn, const char *wallet_backup, const char *wallet_name,
                 const char *u2f_backup, uint8_t replace, int cmd);
#ifdef SIMULATOR
void set_root_dir(const char *path);
#endif


#endif
