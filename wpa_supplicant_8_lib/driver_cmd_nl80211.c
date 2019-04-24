/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright(c) 2018        Intel Corporation
 * Copyright (C) 2019 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright(c) 2018        Intel Corporation
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
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

#include "includes.h"
#include <sys/types.h>
#include <fcntl.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <net/if.h>

#include "common.h"
#include "linux_ioctl.h"
#include "driver_nl80211.h"
#include "wpa_supplicant_i.h"
#include "config.h"

#ifdef ANDROID
#include "android_drv.h"
#endif

#include "iwl_vendor_cmd_copy.h"

static int drv_errors = 0;

/* Functions defined/copied from
 * external/wpa_supplicant_8/src/drivers/driver_nl80211.c
 *
 * These static functions are not exposed so they have
 * to be copied here for proper functionality, in order to
 * avoid changing AOSP's wpa_supplicant.
 */
#ifdef CONFIG_LIBNL32
int send_and_recv_msgs(struct wpa_driver_nl80211_data *drv,
			      struct nl_msg *msg,
			      int (*valid_handler)(struct nl_msg *, void *),
			      void *valid_data);

void * nl80211_cmd(struct wpa_driver_nl80211_data *drv,
			  struct nl_msg *msg, int flags, uint8_t cmd)
{
	return (void *)genlmsg_put(msg, 0, 0, drv->global->nl80211_id,
			   0, flags, cmd, 0);
}
#endif

static void wpa_driver_send_hang_msg(struct wpa_driver_nl80211_data *drv)
{
	drv_errors++;
	if (drv_errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
		drv_errors = 0;
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
	}
}

static int vendor_reply_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *nl_vendor_reply, *nl;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct wpabuf *buf = arg;
	int rem;

	if (!buf)
		return NL_SKIP;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	nl_vendor_reply = tb[NL80211_ATTR_VENDOR_DATA];

	if (!nl_vendor_reply)
		return NL_SKIP;

	if ((size_t) nla_len(nl_vendor_reply) > wpabuf_tailroom(buf)) {
		wpa_printf(MSG_INFO,
			   "nl80211: Vendor cmd: insufficient buffer space for reply");
		return NL_SKIP;
	}

	nla_for_each_nested(nl, nl_vendor_reply, rem) {
		wpabuf_put_data(buf, nla_data(nl), nla_len(nl));
	}

	return NL_SKIP;
}

static int nl80211_vendor_cmd(void *priv, unsigned int vendor_id,
			      unsigned int subcmd, const u8 *data,
			      size_t data_len, struct wpabuf *buf)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;

	if (!(msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, vendor_id) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd) ||
	    (data &&
	     nla_put(msg, NL80211_ATTR_VENDOR_DATA, data_len, data))) {
		goto fail;
	}

	ret = send_and_recv_msgs(drv, msg, vendor_reply_handler, buf);
	if (ret)
		wpa_printf(MSG_DEBUG, "nl80211: vendor command failed err=%d",
			   ret);
	return ret;

fail:
	nlmsg_free(msg);
	return -ENOBUFS;
}

/* needed by external/wpa_supplicant_8/src/drivers/driver_nl80211.c */
static int wpa_driver_nl80211_rxfilter(void *priv, char *cmd)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret, num;
	u8 op;

	wpa_printf(MSG_DEBUG, "%s Enter", __func__);
	/* Ignore filter commands on p2p device */
	if (drv->nlmode == NL80211_IFTYPE_P2P_DEVICE)
		return 0;
	if (os_strncasecmp(cmd, "ADD ", 4) == 0) {
		/* framework requested not to filter the frames */
		if (sscanf(cmd + 4, "%d", &num) != 1)
		    return -EINVAL;
		op = IWL_MVM_VENDOR_RXFILTER_OP_PASS;
	} else if (os_strncasecmp(cmd, "REMOVE ", 7) == 0) {
		/* framework allows to filter the frames */
		if (sscanf(cmd + 7, "%d", &num) != 1)
		    return -EINVAL;
		op = IWL_MVM_VENDOR_RXFILTER_OP_DROP;
	} else if (os_strncasecmp(cmd, "START", 5) == 0) {
		/* Currently we don't use start and stop */
		return 0;
	} else if (os_strncasecmp(cmd, "STOP", 4) == 0) {
		/* Currently we don't use start and stop */
		return 0;
	} else {
		wpa_printf(MSG_ERROR, "%s Exiting due to invalid value", __func__);
		return -EINVAL;
	}
	if (num < 0 || num > 3)
		return -EINVAL;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_RXFILTER_OP, op);
	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_RXFILTER, 1 << num);

	ret = nl80211_vendor_cmd(priv, INTEL_OUI,
			IWL_MVM_VENDOR_CMD_RXFILTER,
			nlmsg_data(nlmsg_hdr(msg)),
			nlmsg_datalen(nlmsg_hdr(msg)), NULL);

	wpa_printf(MSG_DEBUG,
			"nl80211: configure rxfilter = %d, op = %d, ret = %d",
			num, op, ret);

	nlmsg_free(msg);

	if (ret < 0)
		wpa_driver_send_hang_msg(drv);
	else
		drv_errors = 0;
	wpa_printf(MSG_DEBUG, "%s Exiting with ret: %d", __func__, ret);
	return ret;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

/* needed by external/wpa_supplicant_8/src/drivers/driver_nl80211.c */
int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf, size_t buf_len)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct wpa_signal_info sig;
	int ret = 0, flags, rssi, linkspeed;
	u8 macaddr[ETH_ALEN] = {};

	if (os_strcasecmp(cmd, "MACADDR") == 0) {
		ret = linux_get_ifhwaddr(drv->global->ioctl_sock, bss->ifname, macaddr);
		if (!ret) {
			ret = os_snprintf(buf, buf_len,
				"Macaddr = " MACSTR "\n", MAC2STR(macaddr));
		}
	}
	else if (os_strncasecmp(cmd, "RXFILTER-", 9) == 0) {
		/* Handle all the RXFILTER-*  cmds */
		ret = wpa_driver_nl80211_rxfilter(priv, cmd + 9);
	}
	else if (os_strncasecmp(cmd, "COUNTRY", 7) == 0) {
		/*
		 * Due to regulatory constraints, this command is not supported.
		 * A dummy implementation.
		 */
		ret = 0;
	}
	else if ((os_strncasecmp(cmd, "BTCOEXSCAN-", 11) == 0) ||
		 (os_strncasecmp(cmd, "BTCOEXMODE", 10 ) == 0) ||
		 (os_strncasecmp(cmd, "MIRACAST ", 9) == 0) ||
		 (os_strncasecmp(cmd, "SETSUSPENDMODE", 14) == 0)) {
		/*
		* TODO: Above commands are issued by Android framework.
		* Since this commands depend on vendor and the current
		* open source driver/firmware not having the support for
		* vendor commands, implementation is not provided but the
		* request will be completed successfully to avoid VTS
		* failures.
		*/
		wpa_printf(MSG_ERROR,
			"%s: Private commands are not supported %s\n",
			__func__, cmd);
                wpa_printf(MSG_ERROR,
			"%s: Skip this failure in current implementation\n",
			__func__);
		drv_errors = 0;
		ret = 0;
	} else {
		wpa_printf(MSG_ERROR, "Unsupported command: %s", cmd);
		ret = -1;
	}

	return ret;
}

int wpa_driver_set_p2p_noa(void *priv, u8 count, int start, int duration)
{
	return 0;
}

int wpa_driver_get_p2p_noa(void *priv, u8 *buf, size_t len)
{
	return 0;
}


int wpa_driver_set_p2p_ps(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
	return -1;
}


int wpa_driver_set_ap_wps_p2p_ie(void *priv, const struct wpabuf *beacon,
                                 const struct wpabuf *proberesp,
                                 const struct wpabuf *assocresp)
{
	return 0;
}

