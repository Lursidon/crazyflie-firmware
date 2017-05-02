# CrazyFlie's Makefile
# Copyright (c) 2011,2012 Bitcraze AB
# This Makefile compiles all the objet file to ./bin/ and the resulting firmware
# image in ./cfX.elf and ./cfX.bin

# Put your personal build config in tools/make/config.mk and DO NOT COMMIT IT!
# Make a copy of tools/make/config.mk.example to get you started
-include tools/make/config.mk

CFLAGS += $(EXTRA_CFLAGS)

######### JTAG and environment configuration ##########
OPENOCD           ?= openocd
OPENOCD_INTERFACE ?= interface/stlink-v2.cfg
OPENOCD_CMDS      ?=
CROSS_COMPILE     ?= arm-none-eabi-
PYTHON2           ?= python2
DFU_UTIL          ?= dfu-util
CLOAD             ?= 1
DEBUG             ?= 0
CLOAD_SCRIPT      ?= python3 -m cfloader
CLOAD_CMDS        ?=
CLOAD_ARGS        ?=
PLATFORM					?= CF2
LPS_TDMA_ENABLE   ?= 0
LPS_TDOA_ENABLE   ?= 0

######### Stabilizer configuration ##########
##### Sets the name of the stabilizer module to use.
ESTIMATOR          ?= complementary
CONTROLLER         ?= pid
POWER_DISTRIBUTION ?= stock
SENSORS 					 ?= cf2

######### Test activation ##########
FATFS_DISKIO_TESTS  ?= 0	# Set to 1 to enable FatFS diskio function tests. Erases card.

ifeq ($(PLATFORM), CF1)
OPENOCD_TARGET    ?= target/stm32f1x_stlink.cfg
USE_FPU            = 0
endif
ifeq ($(PLATFORM), CF2)
OPENOCD_TARGET    ?= target/stm32f4x_stlink.cfg
USE_FPU           ?= 1
endif


ifeq ($(PLATFORM), CF1)
REV               ?= F
endif
ifeq ($(PLATFORM), CF2)
# Now needed for SYSLINK
CFLAGS += -DUSE_RADIOLINK_CRTP     # Set CRTP link to radio
CFLAGS += -DENABLE_UART          # To enable the uart
REV               ?= D
endif

#OpenOCD conf
RTOS_DEBUG        ?= 0

############### Location configuration ################
FREERTOS = src/lib/FreeRTOS
ifeq ($(USE_FPU), 1)
PORT = $(FREERTOS)/portable/GCC/ARM_CM4F
else
PORT = $(FREERTOS)/portable/GCC/ARM_CM3
endif

ifeq ($(PLATFORM), CF1)
LINKER_DIR = tools/make/F103/linker
ST_OBJ_DIR  = tools/make/F103
endif
ifeq ($(PLATFORM), CF2)
LINKER_DIR = tools/make/F405/linker
ST_OBJ_DIR  = tools/make/F405
endif

#WOLFSSL = src/lib/WolfSSL
WOLFSSLDEFINES = -DNO_WRITEV -DNO_FILESYSTEM -DNO_DEV_RANDOM -DWOLFSSL_USER_IO -DSINGLE_THREADED -DNO_INLINE

WOLFSSLDEFINES += -DNO_WOLFSSL_CLIENT -DNO_WOLFSSL_SERVER -DNO_DES3 -DNO_DSA -DNO_HMAC -DNO_MD4
WOLFSSLDEFINES += -DNO_MD5 -DNO_PWDBASED -DNO_RC4 -DNO_SESSION_CACHE
WOLFSSLDEFINES += -DNO_TLS -DNOWC_NO_RSA_OAEP -DNO_OLD_TLS
WOLFSSLDEFINES += -DNO_ERROR_STRINGS -DNO_WOLFSSL_MEMORY -DNO_DH -DNO_CODING
WOLFSSLDEFINES += -DNO_HC128 -DNO_SHA -DNO_RABBIT -DWOLFCRYPT_ONLY


WOLFSSLDEFINES += -DHAVE_AESGCM -DHAVE_ECC -DRSA_LOW_MEM -DUSE_FAST_MATH
#add aes.c and aes.h
#thigns to define
#
#definitions for porting
#SIZEOF_LONG define in code?
#SIZEOF_LONG_LONG define in code?
#little endian -- nothing to do
#NO_WRITEV -- 
#WOLFSSL_USER_IO -- SEE WHAT I HAVE TO DO THOUGH -/
#NO_FILESYSTEM
#NO_DEV_RANDOM -- ADD SUPPORT FOR TRUERANDOM FROM HARDWARE
#CUSTOM ATOMIC RECORD LAYER PROCESSING
#
#removing features
#NO_WOLFSSL_CLIENT
#NO_DES3
#NO_DSA
#NO_HMAC
#NO_MD4
#NO_MD5
#NO_SHA256
#NO_PWDBASED
#NO_RC4
#NO_SESSION_CACHE
#NO_TLS
#NOWC_NO_RSA_OAEP
# NO_OLD_TLS for the sake of weird stuff
#
#enabling features
#HAVE_AESGCM

LIB = src/lib

################ Build configuration ##################
# St Lib
VPATH_CF1 += $(LIB)/CMSIS/Core/CM3
VPATH_CF1 += $(LIB)/CMSIS/Core/CM3/startup/gcc
CRT0_CF1 = startup_stm32f10x_md.o system_stm32f10x.o

VPATH_CF2 += $(LIB)/CMSIS/STM32F4xx/Source/
VPATH_CF2 += $(LIB)/STM32_USB_Device_Library/Core/src
VPATH_CF2 += $(LIB)/STM32_USB_OTG_Driver/src
VPATH_CF2 += src/deck/api src/deck/core src/deck/drivers/src src/deck/drivers/src/test
CRT0_CF2 = startup_stm32f40xx.o system_stm32f4xx.o

# WolfSSL
VPATH += $(LIB)/WolfSSL/wolfssl
VPATH += $(LIB)/WolfSSL/wolfssl/wolfcrypt
VPATH += $(LIB)/WolfSSL/wolfcrypt/src
VPATH += $(LIB)/WolfSSL/src
#VPATH += $(LIB)/WolfSSL

# Should maybe be in separate file?
-include $(ST_OBJ_DIR)/st_obj.mk

# USB obj
ST_OBJ_CF2 += usb_core.o usb_dcd_int.o usb_dcd.o
# USB Device obj
ST_OBJ_CF2 += usbd_ioreq.o usbd_req.o usbd_core.o

# libdw dw1000 driver
VPATH_CF2 += vendor/libdw1000/src

# FreeRTOS
VPATH += $(PORT)
PORT_OBJ = port.o
VPATH +=  $(FREERTOS)/portable/MemMang
MEMMANG_OBJ = heap_4.o

VPATH += $(FREERTOS)
FREERTOS_OBJ = list.o tasks.o queue.o timers.o $(MEMMANG_OBJ)

#FatFS
VPATH_CF2 += $(LIB)/FatFS
FATFS_OBJ  = diskio.o ff.o syscall.o unicode.o fatfs_sd.o
ifeq ($(FATFS_DISKIO_TESTS), 1)
FATFS_OBJ += diskio_function_tests.o
CFLAGS += -DUSD_RUN_DISKIO_FUNCTION_TESTS
endif

# Crazyflie sources
VPATH += src/init src/hal/src src/modules/src src/utils/src src/drivers/src
VPATH_CF1 += src/platform/cf1
VPATH_CF2 += src/platform/cf2

ifeq ($(PLATFORM), CF1)
VPATH +=$(VPATH_CF1)
endif
ifeq ($(PLATFORM), CF2)
VPATH +=$(VPATH_CF2)
endif

############### Source files configuration ################

# Init
PROJ_OBJ += main.o
PROJ_OBJ_CF1 += platform_cf1.o
PROJ_OBJ_CF2 += platform_cf2.o

# Drivers
PROJ_OBJ += exti.o nvic.o motors.o
PROJ_OBJ_CF1 += led_f103.o i2cdev_f103.o i2croutines.o adc_f103.o mpu6050.o
PROJ_OBJ_CF1 += hmc5883l.o ms5611.o nrf24l01.o eeprom.o watchdog.o
PROJ_OBJ_CF1 += eskylink.o
PROJ_OBJ_CF2 += led_f405.o mpu6500.o i2cdev_f405.o ws2812_cf2.o lps25h.o i2c_drv.o
PROJ_OBJ_CF2 += ak8963.o eeprom.o maxsonar.o piezo.o
PROJ_OBJ_CF2 += uart_syslink.o swd.o uart1.o uart2.o watchdog.o
PROJ_OBJ_CF2 += cppm.o
PROJ_OBJ_CF2 += bmi160.o bma2x2.o bmg160.o bmp280.o bstdr_comm_support.o
# USB Files
PROJ_OBJ_CF2 += usb_bsp.o usblink.o usbd_desc.o usb.o

# Hal
PROJ_OBJ += crtp.o ledseq.o freeRTOSdebug.o buzzer.o
PROJ_OBJ_CF1 += imu_cf1.o pm_f103.o nrf24link.o ow_none.o uart_cf1.o
PROJ_OBJ_CF2 +=  pm_f405.o syslink.o radiolink.o ow_syslink.o proximity.o usec_time.o
PROJ_OBJ_CF2 += aeslink.o

PROJ_OBJ_CF2 +=  sensors_$(SENSORS).o
# libdw
PROJ_OBJ_CF2 += libdw1000.o libdw1000Spi.o

# Modules

#PROJ_OBJ += system.o comm.o console.o pid.o crtpservice.o param.o mem.o
#PROJ_OBJ += rng_interface.o #crtpservice2.o

PROJ_OBJ += system.o comm.o console.o pid.o crtpservice.o param.o

PROJ_OBJ += log.o worker.o trigger.o sitaw.o queuemonitor.o msp.o
PROJ_OBJ_CF1 += sound_cf1.o sensors_cf1.o mem_cf1.o
PROJ_OBJ_CF2 += platformservice.o sound_cf2.o extrx.o sysload.o mem_cf2.o

# Stabilizer modules
PROJ_OBJ += commander.o crtp_commander.o crtp_commander_rpyt.o
PROJ_OBJ += crtp_commander_generic.o crtp_localization_service.o
PROJ_OBJ += attitude_pid_controller.o sensfusion6.o stabilizer.o
PROJ_OBJ += position_estimator_altitude.o position_controller_pid.o
PROJ_OBJ += estimator_$(ESTIMATOR).o controller_$(CONTROLLER).o
PROJ_OBJ += power_distribution_$(POWER_DISTRIBUTION).o


# Deck Core
PROJ_OBJ_CF2 += deck.o deck_info.o deck_drivers.o deck_test.o

# Deck API
PROJ_OBJ_CF2 += deck_constants.o
PROJ_OBJ_CF2 += deck_digital.o
PROJ_OBJ_CF2 += deck_analog.o
PROJ_OBJ_CF2 += deck_spi.o

# Decks
PROJ_OBJ_CF2 += bigquad.o
PROJ_OBJ_CF2 += rzr.o
PROJ_OBJ_CF2 += ledring12.o
PROJ_OBJ_CF2 += buzzdeck.o
PROJ_OBJ_CF2 += gtgps.o
PROJ_OBJ_CF2 += cppmdeck.o
PROJ_OBJ_CF2 += usddeck.o
PROJ_OBJ_CF2 += vl53l0x.o
PROJ_OBJ_CF2 += locodeck.o
ifeq ($(LPS_TDMA_ENABLE), 1)
PROJ_OBJ_CF2 += lpsTwrTdmaTag.o
else
PROJ_OBJ_CF2 += lpsTwrTag.o
endif

ifeq ($(LPS_TDOA_ENABLE), 1)
PROJ_OBJ_CF2 += lpsTdoaTag.o
CFLAGS += -DLPS_TDOA_ENABLE
endif

#Deck tests
PROJ_OBJ_CF2 += exptest.o
#PROJ_OBJ_CF2 += bigquadtest.o


# Utilities
PROJ_OBJ += filter.o cpuid.o cfassert.o  eprintf.o crc.o num.o debug.o
PROJ_OBJ += version.o FreeRTOS-openocd.o
PROJ_OBJ_CF1 += configblockflash.o
PROJ_OBJ_CF2 += configblockeeprom.o

# Libs
PROJ_OBJ_CF2 += libarm_math.a

# Wolfssl 
#PROJ_OBJ += aes.o ssl.o #internal.o error-ssl.o coding.o dirent.o stat.o asn.o dh.o
#PROJ_OBJ += -l$(WOLFSSL)/src #-l$(WOLFSSL)/wolfssl -l$(WOLFSSL)/wolfssl/wolfcrypt
#PROJ_OBJ += -l$(WOLFSSL)/wolfcrypt/src
# removed ones
# crl.o internal.o io.o keys.o ocsp.o sniffer.o ssl.o tls.o
PROJ_OBJ += ssl.o aes.o #WolfSSL/src
PROJ_OBJ += arc4.o asm.o asn.o async.o blake2b.o camellia.o chacha.o
PROJ_OBJ += chacha20_poly1305.o cmac.o coding.o compress.o curve25519.o
PROJ_OBJ += des3.o dh.o dsa.o ecc_fp.o ecc.o ed25519.o error.o fe_low_mem.o fe_operations.o
PROJ_OBJ += ge_low_mem.o ge_operations.o hash.o hc128.o hmac.o idea.o 

PROJ_OBJ += crl.o

PROJ_OBJ += logging.o md2.o
PROJ_OBJ += md4.o md5.o memory.o misc.o pkcs12.o pkcs7.o poly1305.o pwdbased.o
PROJ_OBJ += rabbit.o random.o ripemd.o rsa.o sha.o sha256.o sha512.o signature.o srp.o
PROJ_OBJ += tfm.o wc_encrypt.o wc_port.o wolfevent.o

PROJ_OBJ += io.o ocsp.o sniffer.o tls.o keys.o internal.o integer.o


OBJ = $(FREERTOS_OBJ) $(PORT_OBJ) $(ST_OBJ) $(PROJ_OBJ)
ifeq ($(PLATFORM), CF1)
OBJ += $(CRT0_CF1) $(ST_OBJ_CF1) $(PROJ_OBJ_CF1)
endif
ifeq ($(PLATFORM), CF2)
OBJ += $(CRT0_CF2) $(ST_OBJ_CF2) $(FATFS_OBJ) $(PROJ_OBJ_CF2)
endif

ifdef P
  C_PROFILE = -D P_$(P)
endif

############### Compilation configuration ################
AS = $(CROSS_COMPILE)as
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)gcc
SIZE = $(CROSS_COMPILE)size
OBJCOPY = $(CROSS_COMPILE)objcopy
GDB = $(CROSS_COMPILE)gdb

INCLUDES  = -I$(FREERTOS)/include -I$(PORT) -Isrc
INCLUDES += -Isrc/config -Isrc/hal/interface -Isrc/modules/interface
INCLUDES += -Isrc/utils/interface -Isrc/drivers/interface -Isrc/platform
INCLUDES += -Ivendor/CMSIS/CMSIS/Include

INCLUDES_CF1 += -I$(LIB)/STM32F10x_StdPeriph_Driver/inc
INCLUDES_CF1 += -I$(LIB)/CMSIS/Core/CM3

INCLUDES_CF2 += -I$(LIB)/STM32F4xx_StdPeriph_Driver/inc
INCLUDES_CF2 += -I$(LIB)/CMSIS/STM32F4xx/Include
INCLUDES_CF2 += -I$(LIB)/STM32_USB_Device_Library/Core/inc
INCLUDES_CF2 += -I$(LIB)/STM32_USB_OTG_Driver/inc
INCLUDES_CF2 += -Isrc/deck/interface -Isrc/deck/drivers/interface
INCLUDES_CF2 += -Ivendor/libdw1000/inc
INCLUDES_CF2 += -I$(LIB)/FatFS
INCLUDES_CF2 += -I$(LIB)/WolfSSL
INCLUDES_CF2 += -I$(LIB)/WolfSSL/src
INCLUDES_CF2 += -I$(LIB)/WolfSSL/wolfssl/
INCLUDES_CF2 += -I$(LIB)/WolfSSL/wolfssl/wolfcrypt
INCLUDES_CF2 += -I$(LIB)/WolfSSL/wolfcrypt/src

ifeq ($(USE_FPU), 1)
	PROCESSOR = -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
	CFLAGS += -fno-math-errno -DARM_MATH_CM4 -D__FPU_PRESENT=1 -D__TARGET_FPU_VFP
else
	ifeq ($(PLATFORM), CF1)
		PROCESSOR = -mcpu=cortex-m3 -mthumb
	endif
	ifeq ($(PLATFORM), CF2)
		PROCESSOR = -mcpu=cortex-m4 -mthumb
	endif
endif

#Flags required by the ST library
STFLAGS_CF1 = -DSTM32F10X_MD -DHSE_VALUE=16000000 -include stm32f10x_conf.h -DPLATFORM_CF1
STFLAGS_CF2 = -DSTM32F4XX -DSTM32F40_41xxx -DHSE_VALUE=8000000 -DUSE_STDPERIPH_DRIVER -DPLATFORM_CF2

ifeq ($(DEBUG), 1)
  CFLAGS += -O0 -g3 -DDEBUG
else
	# Fail on warnings
  CFLAGS += -Os -g3 -Werror
endif

ifeq ($(LTO), 1)
  CFLAGS += -flto
endif

ifeq ($(USE_ESKYLINK), 1)
  CFLAGS += -DUSE_ESKYLINK
endif

CFLAGS += -DBOARD_REV_$(REV) -DESTIMATOR_TYPE_$(ESTIMATOR) -DCONTROLLER_TYPE_$(CONTROLLER) -DPOWER_DISTRIBUTION_TYPE_$(POWER_DISTRIBUTION)

CFLAGS += $(PROCESSOR) $(INCLUDES) $(STFLAGS) $(WOLFSSLDEFINES)
ifeq ($(PLATFORM), CF1)
CFLAGS += $(INCLUDES_CF1) $(STFLAGS_CF1)
endif
ifeq ($(PLATFORM), CF2)
CFLAGS += $(INCLUDES_CF2) $(STFLAGS_CF2)
endif

CFLAGS += -Wall -Wmissing-braces -fno-strict-aliasing $(C_PROFILE) -std=gnu11
# Compiler flags to generate dependency files:
CFLAGS += -MD -MP -MF $(BIN)/dep/$(@).d -MQ $(@)
#Permits to remove un-used functions and global variables from output file
CFLAGS += -ffunction-sections -fdata-sections
# Prevent promoting floats to doubles
CFLAGS += -Wdouble-promotion


ASFLAGS = $(PROCESSOR) $(INCLUDES)
LDFLAGS = --specs=nano.specs $(PROCESSOR) -Wl,-Map=$(PROG).map,--cref,--gc-sections,--undefined=uxTopUsedPriority

#Flags required by the ST library
ifeq ($(CLOAD), 1)
  LDFLAGS += -T $(LINKER_DIR)/FLASH_CLOAD.ld
  LOAD_ADDRESS = 0x8004000
else
  LDFLAGS += -T $(LINKER_DIR)/FLASH.ld
  LOAD_ADDRESS = 0x8000000
endif

ifeq ($(LTO), 1)
  LDFLAGS += -Os -flto -fuse-linker-plugin
endif

#Program name
ifeq ($(PLATFORM), CF1)
PROG = cf1
else
PROG = cf2
endif
#Where to compile the .o
BIN = bin
VPATH += $(BIN)

#Dependency files to include
DEPS := $(foreach o,$(OBJ),$(BIN)/dep/$(o).d)

##################### Misc. ################################
ifeq ($(SHELL),/bin/sh)
  COL_RED=\033[1;31m
  COL_GREEN=\033[1;32m
  COL_RESET=\033[m
endif

#################### Targets ###############################


all: check_submodules build
build: clean_version compile print_version size
compile: clean_version $(PROG).hex $(PROG).bin $(PROG).dfu

libarm_math.a:
	+$(MAKE) -C tools/make/cmsis_dsp/ V=$(V)

clean_version:
ifeq ($(SHELL),/bin/sh)
	@echo "  CLEAN_VERSION"
	@rm -f version.c
endif

print_version: compile
ifeq ($(PLATFORM), CF1)
	@echo "Crazyflie Nano (1.0) build!"
endif
ifeq ($(PLATFORM), CF2)
	@echo "Crazyflie 2.0 build!"
endif
	@$(PYTHON2) tools/make/versionTemplate.py --print-version
ifeq ($(CLOAD), 1)
	@echo "Crazyloader build!"
endif
ifeq ($(FATFS_DISKIO_TESTS), 1)
	@echo "WARNING: FatFS diskio tests enabled. Erases SD-card!"
endif

size: compile
	@$(SIZE) -B $(PROG).elf

#Radio bootloader
cload:
ifeq ($(CLOAD), 1)
	$(CLOAD_SCRIPT) $(CLOAD_CMDS) flash $(CLOAD_ARGS) $(PROG).bin stm32-fw
else
	@echo "Only cload build can be bootloaded. Launch build and cload with CLOAD=1"
endif

#Flash the stm.
flash:
	$(OPENOCD) -d2 -f $(OPENOCD_INTERFACE) $(OPENOCD_CMDS) -f $(OPENOCD_TARGET) -c init -c targets -c "reset halt" \
                 -c "flash write_image erase $(PROG).elf" -c "verify_image $(PROG).elf" -c "reset run" -c shutdown

flash_dfu:
	$(DFU_UTIL) -a 0 -D $(PROG).dfu

#STM utility targets
halt:
	$(OPENOCD) -d0 -f $(OPENOCD_INTERFACE) $(OPENOCD_CMDS) -f $(OPENOCD_TARGET) -c init -c targets -c "halt" -c shutdown

reset:
	$(OPENOCD) -d0 -f $(OPENOCD_INTERFACE) $(OPENOCD_CMDS) -f $(OPENOCD_TARGET) -c init -c targets -c "reset" -c shutdown

openocd:
	$(OPENOCD) -d2 -f $(OPENOCD_INTERFACE) $(OPENOCD_CMDS) -f $(OPENOCD_TARGET) -c init -c targets -c "\$$_TARGETNAME configure -rtos auto"

trace:
	$(OPENOCD) -d2 -f $(OPENOCD_INTERFACE) $(OPENOCD_CMDS) -f $(OPENOCD_TARGET) -c init -c targets -f tools/trace/enable_trace.cfg

gdb: $(PROG).elf
	$(GDB) -ex "target remote localhost:3333" -ex "monitor reset halt" $^

erase:
	$(OPENOCD) -d2 -f $(OPENOCD_INTERFACE) -f $(OPENOCD_TARGET) -c init -c targets -c "halt" -c "stm32f4x mass_erase 0" -c shutdown

#Print preprocessor #defines
prep:
	@$(CC) $(CFLAGS) -dM -E - < /dev/null

check_submodules:
	@$(PYTHON2) tools/make/check-for-submodules.py

include tools/make/targets.mk

#include dependencies
-include $(DEPS)

unit:
	rake unit "DEFINES=$(CFLAGS)" "FILES=$(FILES)"
