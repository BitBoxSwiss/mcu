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


#ifndef _BOARD_COM_H_
#define _BOARD_COM_H_


#include <stdint.h>


#define sam4s
#define cortexm4

#define BOARD_FREQ_SLCK_XTAL        (32768U)
#define BOARD_FREQ_SLCK_BYPASS      (32768U)
#define BOARD_FREQ_MAINCK_XTAL      (12000000U)
#define BOARD_FREQ_MAINCK_BYPASS    (12000000U)
#define BOARD_MCK                   CHIP_FREQ_CPU_MAX
#define BOARD_OSC_STARTUP_US        15625

#define LED_0_PIN                   IOPORT_CREATE_PIN(PIOA, 16)
#define LED_0_ACTIVE                false
#define LED_0_INACTIVE              !LED0_ACTIVE
#define LED_COUNT 1

#define ACCESS_MEM_TO_RAM_ENABLED

#define SD_MMC_ENABLE
#define SD_MMC_SPI_MEM_CNT          1
#define SD_MMC_SPI                  SPI

#define SPI_NPCS0_GPIO              (PIO_PA11_IDX)
#define SPI_NPCS0_FLAGS             (PIO_PERIPH_A | PIO_DEFAULT)
#define SPI_NPCS1_GPIO              (PIO_PA9_IDX)
#define SPI_NPCS1_FLAGS             (PIO_PERIPH_B | PIO_DEFAULT)
#define SPI_MISO_GPIO               (PIO_PA12_IDX)
#define SPI_MISO_FLAGS              (PIO_PERIPH_A | PIO_DEFAULT)
#define SPI_MOSI_GPIO               (PIO_PA13_IDX)
#define SPI_MOSI_FLAGS              (PIO_PERIPH_A | PIO_DEFAULT)
#define SPI_SPCK_GPIO               (PIO_PA14_IDX)
#define SPI_SPCK_FLAGS              (PIO_PERIPH_A | PIO_DEFAULT)

#define TWI0_DATA_GPIO   PIO_PA3_IDX
#define TWI0_DATA_FLAGS  (PIO_PERIPH_A | PIO_PULLUP)
#define TWI0_CLK_GPIO    PIO_PA4_IDX
#define TWI0_CLK_FLAGS   (PIO_PERIPH_A | PIO_PULLUP)

#define BOARD_COM_ATAES_ADDR_LEN            2u
#define BOARD_COM_ATAES_ADDR_IO             0xFE00
#define BOARD_COM_ATAES_ADDR_STATUS         0xFFF0
#define BOARD_COM_ATAES_ADDR_RESET          0xFFE0
#define BOARD_COM_ATAES_TWI_DEVICE_ADDR     0x50u
#define BOARD_COM_ATAES_TWI                 TWI0
#define BOARD_COM_ATAES_TWI_ID              ID_TWI0
#define BOARD_COM_ATAES_TWI_SPEED           100000u
#define BOARD_COM_ATAES_SPI_SPEED           10000000u
#define BOARD_COM_ATAES_SPI_INS_WRITE       2u
#define BOARD_COM_ATAES_SPI_INS_READ        3u
#define BOARD_COM_ATAES_SPI_INS_WRDI        4u// Reset write enable register
#define BOARD_COM_ATAES_SPI_INS_RDSR        5u// Read status register
#define BOARD_COM_ATAES_SPI_INS_WREN        6u// Set write enable latch, must be done before each write command


typedef enum BOARD_COM_SPI_DEV {
    BOARD_COM_SPI_DEV_ATAES,
    BOARD_COM_SPI_DEV_SD,
} BOARD_COM_SPI_DEV;

typedef enum BOARD_COM_ATAES_MODE {
    BOARD_COM_ATAES_MODE_SPI,
    BOARD_COM_ATAES_MODE_TWI,
} BOARD_COM_ATAES_MODE;


uint8_t board_com_report_ataes_mode(void);
uint8_t board_com_report_sd_cs(void);
uint32_t board_com_twi_read(uint32_t address, uint8_t *reply, uint16_t reply_len);
uint32_t board_com_twi_write(uint32_t address, uint8_t *buf, uint16_t buf_len);
uint8_t board_com_spi_write_read(BOARD_COM_SPI_DEV d, uint8_t *ins, uint32_t ins_len,
                                 uint8_t *reply, uint32_t reply_len);
uint8_t board_com_spi_write(BOARD_COM_SPI_DEV d, uint8_t *cmd, uint32_t len);
void board_com_init(void);


#endif
