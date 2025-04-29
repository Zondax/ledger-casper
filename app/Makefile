#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2024 Zondax AG
#  (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# Set the default value for PRODUCTION_BUILD to 0 if not already defined
PRODUCTION_BUILD ?= 1

# Display whether this is a production build or for internal use
ifeq ($(PRODUCTION_BUILD), 1)
    $(info ************ PRODUCTION_BUILD  = [PRODUCTION BUILD])
else
    $(info ************ PRODUCTION_BUILD  = [INTERNAL USE])
endif

# Display whether swap functionality is enabled or not
ifeq ($(ENABLE_SWAP), 1)
    $(info ************ HAVE_SWAP  = [ENABLED])
else
    $(info ************ HAVE_SWAP  = [DISABLED])
endif

# Add the PRODUCTION_BUILD definition to the compiler flags
DEFINES += PRODUCTION_BUILD=$(PRODUCTION_BUILD)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN=CSPR
endif
 
VARIANT_PARAM=COIN
VARIANT_VALUES=$(COIN)

include $(CURDIR)/Makefile.version

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOS = nanos_icon.gif
ICON_NANOX = nanox_icon.gif
ICON_NANOSP = nanox_icon.gif
ICON_STAX = stax_icon.gif
ICON_FLEX = flex_icon.gif

$(info COIN  = [$(COIN)])

ifeq ($(COIN),CSPR)
# Main app configuration
DEFINES += APP_STANDARD
APPNAME = "Casper"
APPPATH = "44'/506'"

else ifeq ($(COIN),CSPR_INVALID)
else
define error_message

COIN value not supported: [$(COIN)]

endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = --curve secp256k1 $(COMMON_LOAD_PARAMS) --path ${APPPATH}

ifeq ($(TARGET_NAME),TARGET_NANOS)
	APP_STACK_MIN_SIZE := 1600
else
	APP_STACK_MIN_SIZE := 1752
endif

include $(BOLOS_SDK)/Makefile.target

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

APP_SOURCE_PATH += $(MY_DIR)/../app/src/

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform

CFLAGS += -Wvla

DEFINES += HAVE_HASH HAVE_BLAKE2
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

# Enable QR code display for Flex and Stax
ENABLE_NBGL_QRCODE ?= 1
 
# make rust a prerequisite for all object files 
$(OBJECT_FILES): | rust

.PHONY: rust
rust:
	@echo "No rust code"

.PHONY: rust_clean
rust_clean:
	@echo "No rust code"

clean: rust_clean

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version
