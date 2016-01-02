/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

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


#include "flags.h"


#define X(a) #a,
const char *const CMD_STR[] = { CMD_TABLE };
#undef X

#define X(a) #a,
const char *const ATTR_STR[] = { ATTR_TABLE };
#undef X

#define X(a, b, c) #b,
const char *const FLAG_CODE[] = { FLAG_TABLE };
#undef X

#define X(a, b, c) c,
const char *const FLAG_MSG[] = { FLAG_TABLE };
#undef X

const char *cmd_str(int cmd)
{
    return CMD_STR[cmd];
}


const char *attr_str(int attr)
{
    return ATTR_STR[attr];
}


const char *flag_code(int flag)
{
    return FLAG_CODE[flag];
}


const char *flag_msg(int flag)
{
    return FLAG_MSG[flag];
}
