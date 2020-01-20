#
# Copyright (C) 2014 The Android Open Source Project
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

ifeq ($(WPA_SUPPLICANT_VERSION),VER_2_1_DEVEL)

ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),)
  CONFIG_DRIVER_$(BOARD_WPA_SUPPLICANT_DRIVER) := y
endif

WPA_SUPPL_DIR = external/wpa_supplicant_8
WPA_SRC_FILE :=

include $(WPA_SUPPL_DIR)/wpa_supplicant/android.config


WPA_SUPPL_DIR_INCLUDE = $(WPA_SUPPL_DIR)/src \
        $(WPA_SUPPL_DIR)/src/common \
        $(WPA_SUPPL_DIR)/src/drivers \
        $(WPA_SUPPL_DIR)/src/l2_packet \
        $(WPA_SUPPL_DIR)/src/utils \
        $(WPA_SUPPL_DIR)/src/wps \
        $(WPA_SUPPL_DIR)/wpa_supplicant

ifdef CONFIG_DRIVER_NL80211
WPA_SUPPL_DIR_INCLUDE += external/libnl/include
WPA_SRC_FILE += driver_cmd_nl80211.c
endif

ifdef CONFIG_ANDROID_LOG
L_CFLAGS += -DCONFIG_ANDROID_LOG
endif
L_CFLAGS += \
           -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong \
           -fno-strict-overflow \
           -fwrapv \
           -Wformat -Wformat-security \
           -Wall -Wextra -Wsign-compare -Wpointer-arith \
           -Wno-unused-parameter \
           -Wno-unused-variable \
           -Wno-unused-function \
           -Wno-missing-field-initializers \
           -Wno-int-to-pointer-cast \
           -Wno-conversion-null \
           -Werror \
           -Wnull-dereference

########################

include $(CLEAR_VARS)
LOCAL_MODULE := lib_driver_cmd_intc
LOCAL_PROPRIETARY_MODULE := true
LOCAL_SHARED_LIBRARIES := libc libcutils libnl libnetutils
LOCAL_CFLAGS := $(L_CFLAGS)
LOCAL_SRC_FILES := $(WPA_SRC_FILE)
LOCAL_C_INCLUDES := $(WPA_SUPPL_DIR_INCLUDE) \
	$(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

########################

endif
