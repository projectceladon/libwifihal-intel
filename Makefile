ifndef CXX
CXX=g++
endif

PKG_CONFIG ?= pkg-config

default: all

#=====================================
#	Hal library
#=====================================
HAL = libwifihal.so
HAL_DIR  = $(abspath ./lib)
PY_TESTS = $(abspath ./py_tests)
UTIL_DIR = $(abspath ./util)
INC_DIR  = $(abspath ./include)
INC_IMPORTED_DIR  = $(INC_DIR)/imported

CXXFLAGS = -MMD -O2 -Wall -Wextra -Wno-unused-parameter -g -Wno-missing-field-initializers
$(HAL): CXXFLAGS += -I$(INC_DIR) -I$(INC_IMPORTED_DIR) -I$(HAL_DIR) -I$(UTIL_DIR)
$(HAL): CXXFLAGS += -fPIC
LDFLAGS = -shared

-include .config

HAL_OBJS  = $(HAL_DIR)/wifi_hal.o
HAL_OBJS += $(HAL_DIR)/link_layer_stats.o
HAL_OBJS += $(HAL_DIR)/rtt.o
HAL_OBJS += $(HAL_DIR)/driver_if.o
HAL_OBJS += $(HAL_DIR)/wpa_ctrl.o
HAL_OBJS += $(HAL_DIR)/wpas_if.o
HAL_OBJS += $(HAL_DIR)/gscan.o
HAL_OBJS += $(PY_TESTS)/wifi_hal_wrapper.o
HAL_OBJS += $(UTIL_DIR)/hal_debug.o
HAL_OBJS += $(UTIL_DIR)/utils.o

ifdef CONFIG_DEBUG
ifeq ($(shell expr $(CONFIG_DEBUG) : '[0-3]$\'), 1)
$(HAL): CXXFLAGS += -DCONFIG_DEBUG=$(CONFIG_DEBUG)
else
$(error CONFIG_DEBUG must be an integer between 0 and 3)
endif
endif

ifndef CONFIG_NO_SYSLOG
$(HAL): CXXFLAGS += -DCONFIG_DEBUG_SYSLOG
endif

ifdef CONFIG_DEBUG_STDOUT
$(HAL): CXXFLAGS += -DCONFIG_DEBUG_STDOUT
endif

ifdef CONFIG_GLOBAL_CTRL_IFACE
$(HAL): CXXFLAGS += -DCONFIG_GLOBAL_CTRL_IFACE=\"$(CONFIG_GLOBAL_CTRL_IFACE)\"
endif

ifdef CONFIG_LLS_ENABLED
$(HAL): CXXFLAGS += -DCONFIG_LLS_ENABLED
endif

ifeq ($(NO_PKG_CONFIG),)
NL3xFOUND := $(shell $(PKG_CONFIG) --atleast-version=3.2 libnl-3.0 && echo Y)
ifneq ($(NL3xFOUND),Y)
NL31FOUND := $(shell $(PKG_CONFIG) --exact-version=3.1 libnl-3.1 && echo Y)
ifneq ($(NL31FOUND),Y)
NL3FOUND := $(shell $(PKG_CONFIG) --atleast-version=3 libnl-3.0 && echo Y)
ifneq ($(NL3FOUND),Y)
NL2FOUND := $(shell $(PKG_CONFIG) --atleast-version=2 libnl-2.0 && echo Y)
ifneq ($(NL2FOUND),Y)
NL1FOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-1 && echo Y)
endif
endif
endif
endif

ifeq ($(NL1FOUND),Y)
NLLIBNAME = libnl-1
endif

ifeq ($(NL2FOUND),Y)
CXXFLAGS += -DCONFIG_LIBNL20
LIBS += -lnl-genl
NLLIBNAME = libnl-2.0
endif

ifeq ($(NL3xFOUND),Y)
# libnl 3.2 might be found as 3.2 and 3.0
NL3FOUND = N
CXXFLAGS += -DCONFIG_LIBNL30 -DCONFIG_LIBNL32
LIBS += -lnl-genl-3
NLLIBNAME = libnl-3.0
endif

ifeq ($(NL3FOUND),Y)
CXXFLAGS += -DCONFIG_LIBNL30
LIBS += -lnl-genl
NLLIBNAME = libnl-3.0
endif

# nl-3.1 has a broken libnl-gnl-3.1.pc file
# as show by pkg-config --debug --libs --cflags --exact-version=3.1 libnl-genl-3.1;echo $?
ifeq ($(NL31FOUND),Y)
CXXFLAGS += -DCONFIG_LIBNL30
LIBS += -lnl-genl
NLLIBNAME = libnl-3.1
endif

ifeq ($(NLLIBNAME),)
$(error Cannot find development files for any supported version of libnl)
endif

LIBS += $(shell $(PKG_CONFIG) --libs $(NLLIBNAME))
CXXFLAGS += $(shell $(PKG_CONFIG) --cflags $(NLLIBNAME))
endif # NO_PKG_CONFIG

$(HAL): $(HAL_OBJS)
	@echo Building library=$@
	$(CXX) $(LDFLAGS) -o $@ $^

hal: $(HAL)

-include $(HAL_OBJS:%.o=%.d)

#======================================
#	Hal util
#======================================
HALUTIL = halutil

$(HALUTIL): CXXFLAGS += -I$(INC_IMPORTED_DIR) -I$(HAL_DIR) -I$(UTIL_DIR)
$(HALUTIL): CXXFLAGS += -Wno-unused-variable -Wno-uninitialized

HALUTIL_DIR = $(abspath ./exec/halutil)
HALUTIL_OBJS = $(HALUTIL_DIR)/halutil.o
HALUTIL_OBJS += $(HAL_DIR)/wifi_hal_stub.o
LIBS := -lwifihal -lpthread $(LIBS)

$(HALUTIL): $(HALUTIL_OBJS) | $(HAL)
	@echo Building exec=$@
	$(CXX) -o $@ $^ -L. -Wl,-rpath=./ $(LIBS)

-include $(HALUTIL_OBJS:%.o=%.d)

#======================================
#	Tests
#======================================
HALTESTS = haltests

$(HALTESTS): CXXFLAGS += -I$(HAL_DIR) -I$(UTIL_DIR) -I$(INC_IMPORTED_DIR)
$(HALTESTS): CXXFLAGS += -Wno-unused-variable -Wno-uninitialized

HALTESTS_DIR = $(abspath ./exec/tests)
HALTESTS_OBJS = $(HALTESTS_DIR)/tests.o
HALTESTS_OBJS += $(HALTESTS_DIR)/test-list.o

$(HALTESTS): $(HALTESTS_OBJS) | $(HAL)
	@echo Building exec=$@
	$(CXX)  -o $@ $^ -L. -Wl,-rpath=./ $(LIBS)

#======================================

.PHONY: all hal clean verify_config

verify_config:
	@if [ ! -r .config ]; then \
		echo 'Building wifi hal requires a configuration file(.config).'; \
		echo 'You can run "cp defconfig .config" to create an example'; \
		echo 'configuration.'; \
		exit 1; \
	fi

ALL_BIN = $(HALUTIL) $(HALTESTS)
ALL_LIB = $(HAL)
ALL = $(ALL_LIB) $(ALL_BIN)

all: verify_config $(ALL)

BIN_DEST_DIR ?= /usr/local/sbin
LIB_DEST_DIR ?= /usr/lib


$(DESTDIR)$(BIN_DEST_DIR)/%: %
	install -D $(<) $(@)
$(DESTDIR)$(LIB_DEST_DIR)/%: %
	 install -D $(<) $(@)

install: $(addprefix $(DESTDIR)$(BIN_DEST_DIR)/,$(ALL_BIN))
install: $(addprefix $(DESTDIR)$(LIB_DEST_DIR)/,$(ALL_LIB))

clean:
	rm -f $(ALL) $(HAL_OBJS) $(HAL_OBJS:.o=.d) $(HALUTIL_OBJS) $(HALUTIL_OBJS:.o=.d) $(HALTESTS_OBJS) $(HALTESTS_OBJS:.o=.d)
