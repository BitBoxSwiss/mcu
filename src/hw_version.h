#ifndef _HW_VERSION_H_
#define _HW_VERSION_H_

#include <stdint.h>

typedef enum HW_VERSION {
    HW_VERSION_V1 = 0xFF,
    HW_VERSION_V1_2 = 0x01,
} HW_VERSION;


uint8_t report_hw_version(void);

#endif
