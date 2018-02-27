#include "hw_version.h"
#include "board_com.h"

uint8_t report_hw_version(void)
{
    BOARD_COM_ATAES_MODE ataes_mode = board_com_report_ataes_mode();
    if (ataes_mode == BOARD_COM_ATAES_MODE_SPI) {
        return HW_VERSION_V1_2;
    }
    return HW_VERSION_V1;
}
