#-----------------------------------------------------------------------------
# CmakeLists.txt for the Digital Bitbox.
# Copyright (c) 2015 Lucas Betschart, Douglas J. Bakkum
# MIT License


#-----------------------------------------------------------------------------
# Source files

set(DBB-FIRMWARE-SOURCES
        aes.c
        base58.c
        base64.c
        bip32.c
        commander.c
        hmac.c
        led.c
        memory.c
        pbkdf2.c
        random.c
        ripemd160.c
        ecc.c
        secp256k1.c
        utils.c
        wallet.c
        flags.c
        sha2.c
)

if(USE_UECC_LIB)
    set(DBB-FIRMWARE-SOURCES
        ${DBB-FIRMWARE-SOURCES}
        uECC.c
    )
endif()

set(DBB-BOOTLOADER-SOURCES
        startup.c
        bootloader.c
        led.c
        ecc.c
        uECC.c
        sha2.c
        utils.c
        touch.c
        flags.c
)

set(DBB-HARDWARE-SOURCES
        ataes132.c
        sd.c
        systick.c
        touch.c
        usb.c
)

set(DBB-TEST-SOURCES
        sham.c
)

set(YAJL-SOURCES
        yajl/src/yajl.c
        yajl/src/yajl_lex.c
        yajl/src/yajl_parser.c
        yajl/src/yajl_buf.c
        yajl/src/yajl_encode.c
        yajl/src/yajl_gen.c
        yajl/src/yajl_alloc.c
        yajl/src/yajl_tree.c
        yajl/src/yajl_version.c
)

set(DRIVER-SOURCES
        drivers/common/components/memory/sd_mmc/sd_mmc.c 
        drivers/common/components/memory/sd_mmc/sd_mmc_mem.c 
        drivers/common/components/memory/sd_mmc/sd_mmc_spi.c 
        drivers/common/services/clock/sam4s/sysclk.c 
        drivers/common/services/delay/sam/cycle_counter.c 
        drivers/common/services/serial/usart_serial.c 
        drivers/common/services/sleepmgr/sam/sleepmgr.c 
        drivers/common/services/spi/sam_spi/spi_master.c 
        drivers/common/services/storage/ctrl_access/ctrl_access.c 
        drivers/common/services/usb/class/hid/device/generic/udi_hid_generic.c 
        drivers/common/services/usb/class/hid/device/generic/udi_hid_generic_desc.c 
        drivers/common/services/usb/class/hid/device/udi_hid.c 
        drivers/common/services/usb/udc/udc.c 
        drivers/common/utils/interrupt/interrupt_sam_nvic.c 
        drivers/common/utils/stdio/read.c 
        drivers/common/utils/stdio/write.c 
        drivers/common/boards/user_board/init.c 
        drivers/sam/services/flash_efc/flash_efc.c 
        drivers/sam/drivers/efc/efc.c 
        drivers/sam/drivers/pio/pio.c 
        drivers/sam/drivers/pio/pio_handler.c 
        drivers/sam/drivers/pmc/pmc.c 
        drivers/sam/drivers/pmc/sleep.c 
        drivers/sam/drivers/rtc/rtc.c 
        drivers/sam/drivers/spi/spi.c 
        drivers/sam/drivers/twi/twi.c 
        drivers/sam/drivers/uart/uart.c 
        drivers/sam/drivers/udp/udp_device.c 
        drivers/sam/drivers/usart/usart.c 
        drivers/sam/drivers/wdt/wdt.c 
        drivers/sam/utils/cmsis/sam4s/source/templates/gcc/startup_sam4s.c 
        drivers/sam/utils/cmsis/sam4s/source/templates/system_sam4s.c 
        drivers/sam/utils/syscalls/gcc/syscalls.c 
        drivers/thirdparty/fatfs/fatfs-port-r0.09/diskio.c 
        drivers/thirdparty/fatfs/fatfs-port-r0.09/sam/fattime_rtc.c 
        drivers/thirdparty/fatfs/fatfs-r0.09/src/ff.c
        drivers/thirdparty/fatfs/fatfs-r0.09/src/option/ccsbcs.c 
)


#-----------------------------------------------------------------------------
# Include directories

set(DRIVER-INCLUDES
        drivers/config
        drivers/common/boards
        drivers/common/boards/user_board
        drivers/common/components/memory/sd_mmc
        drivers/common/services/storage/ctrl_access
        drivers/common/services/clock
        drivers/common/services/delay
        drivers/common/services/gpio
        drivers/common/services/ioport
        drivers/common/services/serial/sam_uart
        drivers/common/services/serial
        drivers/common/services/sleepmgr
        drivers/common/services/spi/sam_spi
        drivers/common/services/spi
        drivers/common/services/twi
        drivers/common/services/usb
        drivers/common/services/usb/class/hid
        drivers/common/services/usb/class/hid/device
        drivers/common/services/usb/class/hid/device/generic
        drivers/common/services/usb/udc
        drivers/common/utils
        drivers/common/utils/stdio/stdio_serial
        drivers/sam/utils
        drivers/sam/utils/preprocessor
        drivers/sam/utils/cmsis/sam4s/include
        drivers/sam/utils/header_files
        drivers/sam/drivers/pio
        drivers/sam/drivers/pmc
        drivers/sam/drivers/rtc
        drivers/sam/drivers/spi
        drivers/sam/drivers/twi
        drivers/sam/drivers/uart
        drivers/sam/drivers/usart
        drivers/sam/drivers/udp
        drivers/sam/drivers/wdt
        drivers/sam/drivers/efc
        drivers/sam/services/flash_efc
        drivers/thirdparty/CMSIS/Include
        drivers/thirdparty/fatfs/fatfs-r0.09/src
        drivers/thirdparty/fatfs/fatfs-port-r0.09/sam
        drivers/thirdparty/qtouch/generic/include
)

set(DBB-INCLUDES
        secp256k1
        secp256k1/src
        secp256k1/include
)


#-----------------------------------------------------------------------------
# Warnings

if(WIN32)
  #Disable all the warnings generated by the YAJL library for Windows
  set_source_files_properties( ${YAJL-SOURCES} PROPERTIES
          COMPILE_FLAGS "-w")
endif()


#-----------------------------------------------------------------------------
# Build tests_api

if(BUILD_TYPE STREQUAL "test")
    message(STATUS "C link flags:     ${CMAKE_C_LINK_FLAGS}\n")
    include_directories(${DBB-INCLUDES})
    add_library(bitbox
        STATIC
        ${DBB-FIRMWARE-SOURCES}
        ${DBB-TEST-SOURCES}
        ${YAJL-SOURCES}
    )
endif()


#-----------------------------------------------------------------------------
# Build embedded firmware

if(NOT BUILD_TYPE STREQUAL "test")
    
    if(BUILD_TYPE STREQUAL "firmware")
        set(SOURCES
            ${DBB-HARDWARE-SOURCES} 
            ${DBB-FIRMWARE-SOURCES} 
            ${YAJL-SOURCES} 
            ${DRIVER-SOURCES}
        )
        set(CMAKE_LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/firmware.ld")
    elseif(BUILD_TYPE STREQUAL "bootloader")
        set(SOURCES
            ${DBB-HARDWARE-SOURCES} 
            ${DBB-BOOTLOADER-SOURCES} 
            ${DRIVER-SOURCES}
        )
        set(CMAKE_LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/bootloader.ld")
    endif() 
        
    set(CMAKE_C_LINK_FLAGS "-mthumb -Wl,-Map=\"../bin/${MYPROJECT}.map\" -Wl,--gc-sections -mcpu=cortex-m4 -Wl,--entry=Reset_Handler -Wl,--cref -mthumb -T\"${CMAKE_LINKER_SCRIPT}\"")
    message(STATUS "C link flags:     ${CMAKE_C_LINK_FLAGS}\n")
    include_directories(${DRIVER-INCLUDES})
    include_directories(${DBB-INCLUDES})
    add_library(qtouchlib STATIC IMPORTED)
    set_property(TARGET qtouchlib PROPERTY
                IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/src/drivers/lib/libsam4s-32qt-k-8rs-gnu.a)
    add_library(mathlib STATIC IMPORTED)
    set_property(TARGET mathlib PROPERTY
                IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/src/drivers/lib/libarm_cortexM4l_math.a)
    
    if(BUILD_TYPE STREQUAL "firmware")
        add_executable(${ELF} ${SOURCES} firmware.c)
    elseif(BUILD_TYPE STREQUAL "bootloader")
        add_executable(${ELF} ${SOURCES})
    endif() 
    
    target_link_libraries(${ELF} qtouchlib mathlib)
endif()

