/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum

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


#ifndef USER_BOARD_H
#define USER_BOARD_H


#include <conf_board.h>


/** Board oscillator settings */
#define BOARD_FREQ_SLCK_XTAL        (32768U)
#define BOARD_FREQ_SLCK_BYPASS      (32768U)
#define BOARD_FREQ_MAINCK_XTAL      (12000000U)
#define BOARD_FREQ_MAINCK_BYPASS    (12000000U)

/** Master clock frequency */
#define BOARD_MCK                   CHIP_FREQ_CPU_MAX

/** board main clock xtal startup time */
#define BOARD_OSC_STARTUP_US        15625


#define sam4s
#define cortexm4

#define LED_0_PIN                  IOPORT_CREATE_PIN(PIOA, 16)
#define LED_0_ACTIVE               false
#define LED_0_INACTIVE             !LED0_ACTIVE
#define LED_COUNT 1


#define SD_MMC_SPI_MEM_CNT          1
/* Optional card detect pin and write protection pin
#    define SD_MMC_0_CD_GPIO            (PIO_PA19_IDX)
#    define SD_MMC_0_CD_PIO_ID          ID_PIOA
#    define SD_MMC_0_CD_FLAGS           (PIO_INPUT | PIO_PULLUP)
#    define SD_MMC_0_CD_DETECT_VALUE    0
*/
#define SD_MMC_SPI_0_CS             0
#ifdef  SPI
#define SD_MMC_SPI                  SPI
#else
#define SD_MMC_SPI                  SPI0
#endif
#define SPI_NPCS0_GPIO              (PIO_PA11_IDX)
#define SPI_NPCS0_FLAGS             (PIO_PERIPH_A | PIO_DEFAULT)
#define SPI_MISO_GPIO               (PIO_PA12_IDX)
#define SPI_MISO_FLAGS              (PIO_PERIPH_A | PIO_DEFAULT)
#define SPI_MOSI_GPIO               (PIO_PA13_IDX)
#define SPI_MOSI_FLAGS              (PIO_PERIPH_A | PIO_DEFAULT)
#define SPI_SPCK_GPIO               (PIO_PA14_IDX)
#define SPI_SPCK_FLAGS              (PIO_PERIPH_A | PIO_DEFAULT)

/** TWI0 pin definitions */
#define TWI0_DATA_GPIO   PIO_PA3_IDX
#define TWI0_DATA_FLAGS  (PIO_PERIPH_A | PIO_PULLUP)
#define TWI0_CLK_GPIO    PIO_PA4_IDX
#define TWI0_CLK_FLAGS   (PIO_PERIPH_A | PIO_PULLUP)


#endif // USER_BOARD_H
