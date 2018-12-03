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

#include <stdlib.h>
#include "flash.h"
#include "sam4s4a.h"
#include "core_cm4.h"
#include "mpu.h"

/**
 * MPU REGIONS:
 * 0: whole flash region (bootloader + firmware code)
 *    start: IFLASH0_ADDR, size: IFLASH0_SIZE
 * 1: bootloader region
 *    start: IFLASH0_ADDR, size: FLASH_BOOT_LEN
 * 2: sram region
 *    start: IRAM_ADDR, size: IRAM_SIZE
 * 3: usersig region
 *    start: FLASH_USERSIG_START, size: FLASH_USERSIG_SIZE
 */
static const uint8_t rn_flash = 0;
static const uint8_t rn_boot = 1;
static const uint8_t rn_sram = 2;
static const uint8_t rn_data = 3;
static const uint8_t rn_bss = 4;
static const uint8_t rn_stack = 5;
static const uint8_t rn_usersig = 6;

/**
 * Sets the flash region to read-only.
 */
static void mpu_flash_ro(void)
{
    // Configure flash region
    MPU->RBAR = IFLASH0_ADDR | MPU_REGION_VALID | rn_flash;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size(
                    IFLASH0_SIZE) | MPU_REGION_STATE_RO;
}

/**
 * Enables write access to code region where the firmware resides.
 */
static void mpu_bootloader_ro_firmware_rw(void)
{
    // Configure flash region
    MPU->RBAR = IFLASH0_ADDR | MPU_REGION_VALID | rn_flash;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size(
                    IFLASH0_SIZE) | MPU_REGION_STATE_RW;

    // Configure boot region
    MPU->RBAR = IFLASH0_ADDR | MPU_REGION_VALID | rn_boot;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size(
                    FLASH_BOOT_LEN) | MPU_REGION_STATE_RO;
}

extern uint32_t _srelocate;
extern uint32_t _erelocate;
extern uint32_t _ebss;
extern uint32_t _sbss;
extern uint32_t _sdata;
extern uint32_t _sstack;

/**
 * Enables execution protection for the SRAM region.
 */
static void mpu_sram_nx(void)
{
    // Configure SRAM region, protect from execution
    MPU->RBAR = IRAM_ADDR | MPU_REGION_VALID | rn_sram;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size(
                    IRAM_SIZE) | MPU_REGION_STATE_RO;
    MPU->RBAR = (uint32_t) &_sdata | MPU_REGION_VALID | rn_data;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size((
                    uint32_t) &_erelocate -
                (uint32_t) &_sdata) | MPU_REGION_STATE_RW | MPU_REGION_STATE_XN;

    MPU->RBAR = (uint32_t) &_sbss | MPU_REGION_VALID | rn_bss;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL |
                mpu_region_size((uint32_t) &_ebss - (uint32_t) &_sbss) |
                MPU_REGION_STATE_RW;

    MPU->RBAR = (uint32_t) &_sstack | MPU_REGION_VALID | rn_stack;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size((
                    IRAM_ADDR + IRAM_SIZE) -
                (uint32_t) &_sstack) | MPU_REGION_STATE_RW | MPU_REGION_STATE_XN;
}

/**
 * Enables read-write access to user signature memory.
 */
static void mpu_usersig_rw(void)
{
    MPU->RBAR = FLASH_USERSIG_START | MPU_REGION_VALID | rn_usersig;
    MPU->RASR = MPU_REGION_ENABLE | MPU_REGION_NORMAL | mpu_region_size(
                    FLASH_USERSIG_SIZE) | MPU_REGION_STATE_RW;
}



/**
 * Initializes the memory regions for firmware mode.
 * The complete code region is protected and read-only.
 * SRAM is protected from execution.
 */
void mpu_firmware_init(void)
{
    int i = 0;

    __disable_irq();
    for (i = 0; i < 8; i ++) {
        NVIC->ICER[i] = 0xFFFFFFFF;
    }
    for (i = 0; i < 8; i ++) {
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }
    __DSB();
    __ISB();
    MPU->CTRL = 0;

    mpu_flash_ro();
    mpu_sram_nx();
    mpu_usersig_rw();

    SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk;
    MPU->CTRL = 0x1 | MPU_CTRL_PRIVDEFENA_Msk | MPU_CTRL_HFNMIENA_Msk;
    __DSB();
    __ISB();
    __enable_irq();
}

/**
 * Initializes the memory regions for bootloader mode.
 * The bootloader code is protected, but the memory
 * region for the firmware code is writable.
 * SRAM is protected from execution.
 */
void mpu_bootloader_init(void)
{
    int i = 0;

    __disable_irq();
    for (i = 0; i < 8; i ++) {
        NVIC->ICER[i] = 0xFFFFFFFF;
    }
    for (i = 0; i < 8; i ++) {
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }
    __DSB();
    __ISB();
    MPU->CTRL = 0;

    mpu_bootloader_ro_firmware_rw();
    mpu_sram_nx();

    SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk;
    MPU->CTRL = 0x1 | MPU_CTRL_PRIVDEFENA_Msk | MPU_CTRL_HFNMIENA_Msk;
    __DSB();
    __ISB();
    __enable_irq();
}

