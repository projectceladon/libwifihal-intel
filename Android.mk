LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

include $(LOCAL_PATH)/android.config

INCLUDE_DIR := include
UTIL_DIR := util

LOCAL_REQUIRED_MODULES :=

LOCAL_CPPFLAGS += -Wno-unused-parameter -Wno-int-to-pointer-cast -Wno-missing-field-initializers
LOCAL_CPPFLAGS += \
        -D_FORTIFY_SOURCE=2 \
        -fstack-protector-strong \
        -Wformat -Wformat-security \
        -Wall -Wextra -Wsign-compare -Wpointer-arith \
        -Wcast-qual -Wcast-align \
        -Wno-unused-parameter \
        -Wno-int-to-pointer-cast \
        -Wno-missing-field-initializers \
        -Wno-conversion-null \
        -Werror \
        -Wnull-dereference
LOCAL_CPPFLAGS += -DCONFIG_LIBNL20
LOCAL_CPPFLAGS += -DCONFIG_ANDROID_LOG

ifneq ($(wildcard external/libnl),)
LOCAL_C_INCLUDES += external/libnl/include
else
LOCAL_C_INCLUDES += external/libnl-headers
endif

LOCAL_C_INCLUDES += \
        $(call include-path-for, libhardware_legacy)/hardware_legacy \
	$(LOCAL_PATH)/$(UTIL_DIR) \
	$(LOCAL_PATH)/$(INCLUDE_DIR) \

LOCAL_SRC_FILES := \
        lib/wifi_hal.cpp \
	$(UTIL_DIR)/hal_debug.cpp \
	lib/driver_if.cpp \

ifdef CONFIG_DEBUG
ifeq ($(shell expr $(CONFIG_DEBUG) : '[0-3]$\'), 1)
LOCAL_CPPFLAGS += -DCONFIG_DEBUG=$(CONFIG_DEBUG)
else
$(error CONFIG_DEBUG must be an integer between 0 and 3)
endif
endif

LOCAL_HEADER_LIBRARIES := libutils_headers

LOCAL_MODULE := libwifi-hal-intel
LOCAL_PROPRIETARY_MODULE := true

include $(BUILD_STATIC_LIBRARY)

include $(LOCAL_PATH)/wpa_supplicant_8_lib/Android.mk
