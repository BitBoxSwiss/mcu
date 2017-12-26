/*

 The MIT License (MIT)

 Copyright (c) 2017 Douglas J. Bakkum

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


#include <string.h>

#include "board_com.h"
#include "spi_master.h"
#include "flags.h"
#include "mcu.h"


#define board_com_build_word_address(p_u8, addr) \
do {\
    p_u8[0] = (uint8_t)(addr >> 8);\
    p_u8[1] = (uint8_t)(addr & 0xFF);\
} while (0)


static BOARD_COM_ATAES_MODE board_com_ataes_mode;
static uint8_t board_com_sd_cs;
static uint8_t board_com_initialized = 0;
static struct spi_device spi_devices[] = {
    { .id = 0 },// Chip select
    { .id = 1 },// Chip select
};


static void board_com_check_ataes_mode(void)
{
    uint8_t status;
    board_com_ataes_mode =
        (board_com_twi_read(BOARD_COM_ATAES_ADDR_STATUS, &status, 1) == TWI_SUCCESS) ?
        BOARD_COM_ATAES_MODE_TWI :
        BOARD_COM_ATAES_MODE_SPI;
}


uint8_t board_com_report_ataes_mode(void)
{
    board_com_init();
    return board_com_ataes_mode;
}


uint8_t board_com_report_sd_cs(void)
{
    board_com_init();
    return board_com_sd_cs;
}


uint32_t board_com_twi_read(uint32_t address, uint8_t *reply, uint16_t reply_len)
{
    twi_package_t twi_package;
    twi_package.chip = BOARD_COM_ATAES_TWI_DEVICE_ADDR;
    board_com_build_word_address(twi_package.addr, address);
    twi_package.addr_length = BOARD_COM_ATAES_ADDR_LEN;
    twi_package.buffer = reply;
    twi_package.length = reply_len;
    return twi_master_read(BOARD_COM_ATAES_TWI, &twi_package);
}


uint32_t board_com_twi_write(uint32_t address, uint8_t *buf, uint16_t buf_len)
{
    twi_package_t twi_package;
    twi_package.chip = BOARD_COM_ATAES_TWI_DEVICE_ADDR;
    board_com_build_word_address(twi_package.addr, address);
    twi_package.addr_length = BOARD_COM_ATAES_ADDR_LEN;
    twi_package.buffer = buf;
    twi_package.length = buf_len;
    return twi_master_write(BOARD_COM_ATAES_TWI, &twi_package);
}


uint8_t board_com_spi_write_read(BOARD_COM_SPI_DEV d, uint8_t *ins, uint32_t ins_len,
                                 uint8_t *reply, uint32_t reply_len)
{
    uint8_t ret = 0;
    board_com_init();
    spi_select_device(SPI, &spi_devices[d]);
    ret = ret || spi_write_packet(SPI, ins, ins_len);
    ret = ret || spi_read_packet(SPI, reply, reply_len);
    spi_deselect_device(SPI, &spi_devices[d]);
    return ret;
}


uint8_t board_com_spi_write(BOARD_COM_SPI_DEV d, uint8_t *cmd, uint32_t len)
{
    uint8_t ret = 0;
    board_com_init();
    spi_select_device(SPI, &spi_devices[d]);
    ret = ret || spi_write_packet(SPI, cmd, len);
    spi_deselect_device(SPI, &spi_devices[d]);
    return ret;
}


void board_com_init(void)
{
    if (!board_com_initialized) {
        // PINS
        ioport_init();
        ioport_set_pin_level(LED_0_PIN, !LED_0_ACTIVE);
        ioport_set_pin_dir(LED_0_PIN, IOPORT_DIR_OUTPUT);
        gpio_configure_pin(TWI0_DATA_GPIO, TWI0_DATA_FLAGS);
        gpio_configure_pin(TWI0_CLK_GPIO, TWI0_CLK_FLAGS);
        gpio_configure_pin(SPI_MISO_GPIO, SPI_MISO_FLAGS);
        gpio_configure_pin(SPI_MOSI_GPIO, SPI_MOSI_FLAGS);
        gpio_configure_pin(SPI_SPCK_GPIO, SPI_SPCK_FLAGS);
        gpio_configure_pin(SPI_NPCS0_GPIO, SPI_NPCS0_FLAGS);
        gpio_configure_pin(SPI_NPCS1_GPIO, SPI_NPCS1_FLAGS);

        // I2C
        twi_options_t opts = {
            .master_clk = sysclk_get_cpu_hz(),
            .speed = BOARD_COM_ATAES_TWI_SPEED,
            .smbus = 0
        };
        sysclk_enable_peripheral_clock(BOARD_COM_ATAES_TWI_ID);
        twi_master_init(BOARD_COM_ATAES_TWI, &opts);

        board_com_check_ataes_mode();

        // SPI
        if (!spi_is_enabled(SPI)) {
            spi_master_init(SPI);
            spi_enable(SPI);
        }
        if (board_com_ataes_mode == BOARD_COM_ATAES_MODE_SPI) {
            board_com_sd_cs = 1;
            spi_master_setup_device(SPI, &spi_devices[0], SPI_MODE_0, BOARD_COM_ATAES_SPI_SPEED,
                                    0);// ATAES SPI setup; SD card SPI set up in sd_mmc_spi.c
        } else {
            board_com_sd_cs = 0;
        }
    }
    board_com_initialized = 1;
}


