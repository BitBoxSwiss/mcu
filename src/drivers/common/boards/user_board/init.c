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


#include <board.h>
#include <gpio.h>
#include <ioport.h>
#include <wdt.h>

#include "mcu.h"
#include "conf_board.h"


void board_init(void)
{
	/* GPIO has been deprecated, the old code just keeps it for compatibility.
	 * In new designs IOPORT is used instead.
	 * Here IOPORT must be initialized for others to use before setting up IO.
	 */
	ioport_init();

	/* Initialize LED0, turned off */
	ioport_set_pin_level(LED_0_PIN, !LED_0_ACTIVE);
	ioport_set_pin_dir(LED_0_PIN, IOPORT_DIR_OUTPUT);


#ifdef CONF_BOARD_UART_CONSOLE
	/* Configure UART pins */
	gpio_configure_group(PINS_UART1_PIO, PINS_UART1, PINS_UART1_FLAGS);
#endif

#ifdef CONF_BOARD_TWI0
	gpio_configure_pin(TWI0_DATA_GPIO, TWI0_DATA_FLAGS);
	gpio_configure_pin(TWI0_CLK_GPIO, TWI0_CLK_FLAGS);
#endif

	/* Configure SPI pins */
#ifdef CONF_BOARD_SPI
	gpio_configure_pin(SPI_MISO_GPIO, SPI_MISO_FLAGS);
	gpio_configure_pin(SPI_MOSI_GPIO, SPI_MOSI_FLAGS);
	gpio_configure_pin(SPI_SPCK_GPIO, SPI_SPCK_FLAGS);

	/**
	 * For NPCS 1, 2, and 3, different PINs can be used to access the same NPCS line.
	 * Depending on the application requirements, the default PIN may not be available.
	 * Hence a different PIN should be selected using the CONF_BOARD_SPI_NPCS_GPIO and
	 * CONF_BOARD_SPI_NPCS_FLAGS macros.
	 */
#ifdef CONF_BOARD_SPI_NPCS0
	gpio_configure_pin(SPI_NPCS0_GPIO, SPI_NPCS0_FLAGS);
#endif

/*
#ifdef CONF_BOARD_SPI_NPCS1
#if defined(CONF_BOARD_SPI_NPCS1_GPIO) && defined(CONF_BOARD_SPI_NPCS1_FLAGS)
	gpio_configure_pin(CONF_BOARD_SPI_NPCS1_GPIO, CONF_BOARD_SPI_NPCS1_FLAGS);
#else
	gpio_configure_pin(SPI_NPCS1_PA9_GPIO, SPI_NPCS1_PA9_FLAGS);
#endif
#endif

#ifdef CONF_BOARD_SPI_NPCS2
#if defined(CONF_BOARD_SPI_NPCS2_GPIO) && defined(CONF_BOARD_SPI_NPCS2_FLAGS)
	gpio_configure_pin(CONF_BOARD_SPI_NPCS2_GPIO, CONF_BOARD_SPI_NPCS2_FLAGS);
#else
	gpio_configure_pin(SPI_NPCS2_PA10_GPIO, SPI_NPCS2_PA10_FLAGS);
#endif
#endif

#ifdef CONF_BOARD_SPI_NPCS3
#if defined(CONF_BOARD_SPI_NPCS3_GPIO) && defined(CONF_BOARD_SPI_NPCS3_FLAGS)
	gpio_configure_pin(CONF_BOARD_SPI_NPCS3_GPIO, CONF_BOARD_SPI_NPCS3_FLAGS);
#else
	gpio_configure_pin(SPI_NPCS3_PA22_GPIO, SPI_NPCS3_PA22_FLAGS);
#endif
#endif
*/
#endif /* CONF_BOARD_SPI */


#ifdef CONF_BOARD_SD_MMC_HSMCI
	/* Configure HSMCI pins */
	gpio_configure_pin(PIN_HSMCI_MCCDA_GPIO, PIN_HSMCI_MCCDA_FLAGS);
	gpio_configure_pin(PIN_HSMCI_MCCK_GPIO, PIN_HSMCI_MCCK_FLAGS);
	gpio_configure_pin(PIN_HSMCI_MCDA0_GPIO, PIN_HSMCI_MCDA0_FLAGS);
	gpio_configure_pin(PIN_HSMCI_MCDA1_GPIO, PIN_HSMCI_MCDA1_FLAGS);
	gpio_configure_pin(PIN_HSMCI_MCDA2_GPIO, PIN_HSMCI_MCDA2_FLAGS);
	gpio_configure_pin(PIN_HSMCI_MCDA3_GPIO, PIN_HSMCI_MCDA3_FLAGS);

	/* Configure SD/MMC card detect pin */
	//gpio_configure_pin(SD_MMC_0_CD_GPIO, SD_MMC_0_CD_FLAGS);
#endif

}
