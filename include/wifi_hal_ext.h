/******************************************************************************
 *
 * This file is provided under a BSD license.  When using or redistributing
 * this file, you may do so under this license.
 *
 * BSD LICENSE
 *
 * Copyright(c) 2014 Intel Mobile Communications GmbH.
 * Copyright(c) 2014 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#ifndef __WIFI_HAL_EXT_H__
#define __WIFI_HAL_EXT_H__

#include <net/if.h>
#include <pthread.h>
#include "utils.h"
#include "wifi_hal.h"
#include "ieee802_11_defs.h"

struct wifi_interface_info {
        u32 magic;

        wifi_handle handle;
        char name[IF_NAMESIZE + 1];
        u32 index;
	u8 mac_addr[ETH_ALEN];
	wifi_interface_mode mode;
};

struct wifi_info {
        u32 magic;

        u32 num_ifaces;
        struct wifi_interface_info **ifaces;

        void *drv;
};

#endif /* __WIFI_HAL_EXT_H__ */
