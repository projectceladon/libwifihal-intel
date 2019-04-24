/*
 * Copyright (C) 2015 Intel Deutschland GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <math.h>

#include "utils.h"
#include "iwl_vendor_cmd_copy.h"
#include "driver_if.h"
#include "nl80211_copy.h"
#include "hal_debug.h"

/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)

#define nl_sock nl_handle

static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
	nl_handle_destroy(h);
}

static inline int nl_socket_set_buffer_size(struct nl_sock *sk,
					    int rxbuf, int txbuf)
{
	return nl_set_buffer_size(sk, rxbuf, txbuf);
}

#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 */

/* C++ compatability */

/**
 * nla_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */

#undef nla_for_each_nested
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, (struct nlattr *)nla_data(nla), nla_len(nla), \
			  rem)

/**
 * struct iface_limits - define interface limits.
 * See cfg80211.h for reference.
 */
struct iface_limits {
	u16 max;
	u16 types;
};

/**
 * struct iface_combs - define interface combinations.
 * See cfg80211.h for reference.
 */
struct iface_combs {
	const struct iface_limits *limits;
	u8 n_limits;
	u32 n_diff_channels;
	u16 n_ifaces;
};

#define CHAN_FLAG_DISABLED BIT(0)
#define CHAN_FLAG_NO_IR BIT(1)
#define CHAN_FLAG_RADAR BIT(2)

/**
 * struct channel_info - channel information
 */
struct channel_info {
	u8 channel;
	u32 freq;
	u32 flags;
};

/**
 * struct band_info - band information
 */
struct band_info {
	u8 band;
	struct channel_info *channels;
	u32 n_channels;
};

struct ftm_data {
	int last_req_id;
	u64 last_req_cookie;
	u32 max_2_sided;
	u32 max_total;
	struct dl_list cur_response;
};

#define DRV_POLL_TIMEOUT_SEC 5

struct drv_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
	struct nl_sock *nl_event;
	struct nl_sock *nl_rtt;
	struct nl_cb *nl_cb;

	u32 ifidx;
	u32 iftypes;
	u32 wiphy_idx;

	struct iface_combs *combs;
	u32 n_combs;

	struct band_info *bands;
	u32 n_bands;
	u8 last_band;

	bool pno_supported;
#ifdef ENABLE_TDLS
	bool tdls_supported;
#endif // ENABLE_TDLS
	bool self_managed_reg;
	struct ftm_data ftm;

	/* Assumes that the event loop is running in a different thread */
	pthread_mutex_t sync;
	pthread_t event_thread;
	bool in_cleanup;
	bool initialized;
	void *handle;
	drv_event_cb event_cb;
};

#define DRV_NOT_INIT(_drv, _str) ({                                            \
	int ret = !!(!_drv || !_drv->initialized);                             \
	if (ret)                                                               \
		hal_printf(MSG_ERROR, "%s called when not initialized", _str); \
	(ret);                                                                 \
})

static struct nl_msg *alloc_nl80211_cmd_msg(struct drv_state *drv,
					    int flags, uint8_t cmd)
{
	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) {
		hal_printf(MSG_ERROR, "Failed to allocate nl80211 message!");
		return NULL;
	}

	if (!(genlmsg_put(msg, 0, 0, drv->nl80211_id, 0, flags, cmd, 0))) {
		nlmsg_free(msg);
		hal_printf(MSG_ERROR, "Failed to configure nl80211 message!");
		return NULL;
	}
	return msg;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = (int *)arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;
	*ret = 0;
	return NL_STOP;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

/**
 * channel_to_freq - convert channel number to frequency
 * @channel_number: the channel number to convert
 *
 * Returns the channel frequency in MHz.
 */

static void drv_vendor_event(struct drv_state *drv, struct nlattr **tb)
{
	u32 vendor_id, subcmd;

	if (!tb[NL80211_ATTR_VENDOR_ID] || !tb[NL80211_ATTR_VENDOR_SUBCMD])
		return;

	vendor_id = nla_get_u32(tb[NL80211_ATTR_VENDOR_ID]);
	subcmd = nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]);

	hal_printf(MSG_DEBUG, "Vendor event: vendor_id=0x%x subcmd=%u",
		   vendor_id, subcmd);
}

static int send_and_recv_sock(struct drv_state *drv, struct nl_msg *msg,
			      int (*valid_handler)(struct nl_msg *, void *),
			      void *valid_data, struct nl_sock *socket)
{
	struct nl_cb *cb;
	int err = -ENOMEM;
	struct nl_sock *sock = socket ? socket : drv->nl_sock;

	cb = nl_cb_clone(drv->nl_cb);
	if (!cb) {
		hal_printf(MSG_ERROR, "Failed to clone nl80211 callback!");
		goto out;
	}

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		hal_printf(MSG_ERROR, "Failed to send nl80211 message!");
		goto out;
	}

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler,
		  &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	err = 1;
	while (err > 0) {
		int res = nl_recvmsgs(sock, cb);
		if (res < 0)
			hal_printf(MSG_DEBUG,
				   "nl80211: nl_recvmsgs failed: %d", res);
	}

 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}

static int send_and_recv(struct drv_state *drv, struct nl_msg *msg,
			      int (*valid_handler)(struct nl_msg *, void *),
			      void *valid_data)
{
	return send_and_recv_sock(drv, msg, valid_handler, valid_data,
				  drv->nl_sock);
}

static int nl80211_init_socket(struct nl_sock **nl_sock, struct nl_cb *cb)
{
	*nl_sock = nl_socket_alloc();
	if (!*nl_sock) {
		hal_printf(MSG_ERROR, "Failed to allocate netlink socket!");
		return -ENOMEM;
	}

	nl_socket_set_cb(*nl_sock, cb);
	nl_socket_set_buffer_size(*nl_sock, 8192, 8192);

	if (genl_connect(*nl_sock)) {
		hal_printf(MSG_ERROR, "Failed to connect to generic netlink!");
		nl_socket_free(*nl_sock);
		return -ENOLINK;
	}

	return 0;
}
static int drv_vendor_cmd(struct drv_state *drv, unsigned int subcmd,
			  const u8 *data, size_t data_len, int flags,
			  int (*valid_handler)(struct nl_msg *, void *),
			  void *arg)
{
	struct nl_msg *msg;
	int ret = 0;

	msg = alloc_nl80211_cmd_msg(drv, flags, NL80211_CMD_VENDOR);
	if (!msg)
		return -1;

	hal_printf(MSG_DEBUG, "subcmd= %d",subcmd);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd);
	if (data)
		NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, data_len, data);
	ret = send_and_recv(drv, msg, valid_handler, arg);
	if (ret)
		hal_printf(MSG_ERROR, "vendor command failed err=%d", ret);
	return ret;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

struct family_data {
	const char *group;
	int id;
};

static int family_handler(struct nl_msg *msg, void *arg)
{
	struct family_data *res = (struct family_data *)arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)
		nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int i;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX,
			  (nlattr *)nla_data(mcgrp),
			  nla_len(mcgrp), NULL);

		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
		    strncmp((const char *)nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
			    res->group,
			    nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
			continue;

		res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	};

	return NL_SKIP;
}

static int nl_get_mc_group_id(struct drv_state *drv,
			      const char *family, const char *group)
{
	struct nl_msg *msg;
	int ret = -1;
	struct family_data res = {group, -ENOENT};

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(drv->nl_sock, "nlctrl"),
		    0, 0, CTRL_CMD_GETFAMILY, 0);

	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = send_and_recv(drv, msg, family_handler, &res);
	msg = NULL;
	if (ret == 0)
		ret = res.id;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int nl80211_mc_groups(struct drv_state *drv)
{
	int ret;

#define REGISTER_MC_GROUP(_str) \
do { \
	ret = nl_get_mc_group_id(drv, NL80211_GENL_NAME, _str); \
	if (ret >= 0) \
		ret = nl_socket_add_membership(drv->nl_event, ret); \
	if (ret < 0) { \
		hal_printf(MSG_ERROR, "Failed to add %s mc group events", \
			   _str); \
		return ret; \
	} \
} while (0)

	REGISTER_MC_GROUP("scan");
	REGISTER_MC_GROUP("config");
	REGISTER_MC_GROUP("mlme");
	REGISTER_MC_GROUP("regulatory");
	REGISTER_MC_GROUP("vendor");

#undef REGISTER_MC_GROUP

	return 0;
}

/**
 * wiphy_info_supp_cmds - get the information about supported cmds
 * @tb - the supported commands attributes
 * @drv - a pointer to the driver state
 *
 * Check for specific supported commands and updates the drv state
 * accordingly.
 */
static void wiphy_info_supp_cmds(struct nlattr *tb,
				 struct drv_state *drv)
{
	struct nlattr *nl_cmd;
	int i;

	if (!tb || !drv)
		return;

	nla_for_each_nested(nl_cmd, tb, i) {
		switch (nla_get_u32(nl_cmd)) {
		case NL80211_CMD_START_SCHED_SCAN:
			drv->pno_supported = true;
			break;
		}
	}
}

/**
 * freq_to_channel - covert a frequency to channel index
 * @freq - the freq to convert
 *
 * Returns the channel index on success, otherwise 0.
 */
static u8 freq_to_channel(u32 freq)
{
	if (freq == 2484)
		return 14;
	else if (freq >= 2412 && freq <= 2472)
		return (freq - 2407) / 5;
	else if (freq >= 5180 && freq <= 5845)
		return (freq - 5000) / 5;

	return 0;
}

/**
 * wiphy_info_freqs - get the information about freqs in a band.
 * @tb - the freqs attribute.
 * @drv - a pointer to the driver state
 * Returns 0 on success and negative value if the combinations are broken.
 */
static int wiphy_info_freqs(struct nlattr *tb,
			    struct band_info *band)
{
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nlattr *nl_freq;
	struct channel_info *chan;
	int rem_freq;
	u32 new_channels = 0, idx;

	if (!tb)
		return NL_OK;

	nla_for_each_nested(nl_freq, tb, rem_freq) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			  (nlattr *)nla_data(nl_freq), nla_len(nl_freq),
			  NULL);
		if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
			continue;

		new_channels++;
	}

	hal_printf(MSG_TRACE, "Processing freqs. num=%u", new_channels);

	chan = (struct channel_info *)
		realloc(band->channels,
			(band->n_channels + new_channels) *
			sizeof(channel_info));

	if (!chan) {
		hal_printf(MSG_ERROR, "channel_info allocation failed");
		return -1;
	}

	band->channels = chan;
	idx = band->n_channels;
	band->n_channels += new_channels;

	nla_for_each_nested(nl_freq, tb, rem_freq) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			  (nlattr *)nla_data(nl_freq), nla_len(nl_freq),
			  NULL);

		if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
			continue;

		if (idx >= band->n_channels) {
			hal_printf(MSG_ERROR,
				   "exceeding channel array limits");
			return 0;
		}

		band->channels[idx].freq =
			nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

		band->channels[idx].channel =
			freq_to_channel(band->channels[idx].freq);

		band->channels[idx].flags = 0;

		if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
			band->channels[idx].flags |= CHAN_FLAG_DISABLED;

		if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR])
			band->channels[idx].flags |= CHAN_FLAG_NO_IR;

		if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
			band->channels[idx].flags |= CHAN_FLAG_RADAR;

		hal_printf(MSG_DEBUG, "Processing freq=%u, flags=0x%X",
			   band->channels[idx].freq,
			   band->channels[idx].flags);
		idx++;
	}

	return 0;
}

/**
 * wiphy_info_single_band - get the information about single band
 * @nl_band - the band attribute.
 * @drv - a pointer to the driver state
 * Returns 0 on success and negative value if the combinations are broken.
 */
static int wiphy_info_single_band(struct nlattr *nl_band,
				  struct drv_state *drv)
{
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct band_info *band;


	if (drv->last_band != nl_band->nla_type) {
		hal_printf(MSG_DEBUG, "Processing band=%u", nl_band->nla_type);
		band = (struct band_info *)
			realloc(drv->bands,
				(drv->n_bands + 1) *
				sizeof(struct band_info));

		if (!band) {
			hal_printf(MSG_ERROR,
				   "band_info allocation failed");
			return -1;
		}
		drv->bands = band;
		band = &drv->bands[drv->n_bands];
		memset(band, 0, sizeof(*band));

		band->band = nl_band->nla_type;
		drv->last_band = nl_band->nla_type;

		drv->n_bands++;

	} else {
		band = &drv->bands[drv->n_bands - 1];
	}

	/* currently only interested in the channel information */
	nla_parse(tb_band, NL80211_BAND_ATTR_MAX,
		  (nlattr *)nla_data(nl_band), nla_len(nl_band), NULL);

	return wiphy_info_freqs(tb_band[NL80211_BAND_ATTR_FREQS], band);
}

/**
 * wiphy_info_supported_bands - get the information about supported bands.
 * @bands - the bands attribute.
 * @drv - a pointer to the driver state
 * Returns 0 on success and negative value if the combinations are broken.
 */
static int wiphy_info_supported_bands(struct nlattr *bands,
				      struct drv_state *drv)
{
	struct nlattr *nl_band;
	int rem_band;

	if (!bands || !drv)
		return -1;

	if (!drv->n_bands)
		hal_printf(MSG_DEBUG, "Processing bands");

	nla_for_each_nested(nl_band, bands, rem_band)
		if (wiphy_info_single_band(nl_band, drv) < 0)
			return -1;

	return 0;
}

/**
 * wiphy_info_parse_single_comb - parse a single interface combination
 * @comb_attr - the combination attribute
 * @combination - will hold the parsed combination
 * Returns 0 on success and negative value if the combination is broken.
 */
static int wiphy_info_parse_single_comb(struct nlattr *comb_attr,
					struct iface_combs *combination)
{
	struct nlattr *tb_comb[NUM_NL80211_IFACE_COMB];
	struct nlattr *tb_limit[NUM_NL80211_IFACE_LIMIT];
	struct nlattr *nl_limit;
	int err, rem_limit;

	err = nla_parse_nested(tb_comb, MAX_NL80211_IFACE_COMB,
			       comb_attr, NULL);
	if (err ||
	    !tb_comb[NL80211_IFACE_COMB_LIMITS] ||
	    !tb_comb[NL80211_IFACE_COMB_MAXNUM] ||
	    !tb_comb[NL80211_IFACE_COMB_NUM_CHANNELS]) {
		hal_printf(MSG_ERROR, "Broken interface combination");
		return -1;
	}

	combination->n_limits = 0;
	combination->n_diff_channels =
		nla_get_u32(tb_comb[NL80211_IFACE_COMB_NUM_CHANNELS]);
	combination->n_ifaces =
		nla_get_u32(tb_comb[NL80211_IFACE_COMB_MAXNUM]);
	combination->limits = NULL;

	hal_printf(MSG_DEBUG, "Combination: diff_chan=%u, max_iface=%u",
		   combination->n_diff_channels, combination->n_ifaces);

	nla_for_each_nested(nl_limit, tb_comb[NL80211_IFACE_COMB_LIMITS],
			    rem_limit) {
		struct iface_limits *cur_limits;
		struct nlattr *nl_mode;
		int rem_mode;

		err = nla_parse_nested(tb_limit, MAX_NL80211_IFACE_LIMIT,
				       nl_limit, NULL);
		if (err || !tb_limit[NL80211_IFACE_LIMIT_MAX] ||
		    !tb_limit[NL80211_IFACE_LIMIT_TYPES]) {
			hal_printf(MSG_ERROR,
				   "Broken interface combination - limits");
			goto fail_comb;
		}

		combination->n_limits++;
		combination->limits = (iface_limits *)
			realloc((void *)combination->limits,
				combination->n_limits * sizeof(iface_limits));

		if (!combination->limits) {
			hal_printf(MSG_ERROR,
				   "Interface combination - failed allocation");
			goto fail_comb;
		}

		cur_limits = const_cast<iface_limits *>
                        (&combination->limits[combination->n_limits - 1]);
		cur_limits->max =
			nla_get_u32(tb_limit[NL80211_IFACE_LIMIT_MAX]);
		cur_limits->types = 0;
		nla_for_each_nested(nl_mode,
				    tb_limit[NL80211_IFACE_LIMIT_TYPES],
				    rem_mode) {
			cur_limits->types |= BIT(nla_type(nl_mode));
		}
		hal_printf(MSG_DEBUG, "limits %d: max=%u types=0x%X",
			   combination->n_limits,
			   cur_limits->max,
			   cur_limits->types);
	}

	return 0;

fail_comb:
	free((void *)combination->limits);
	return -1;
}

/**
 * wiphy_info_parse_combs - parse all the interface combinations
 * @combs_attr - the combinations attribute
 * @drv - a pointer to the driver state
 * Returns 0 on success and negative value if the combinations are broken.
 */
static int wiphy_info_parse_combs(struct nlattr *combs_attr,
				  struct drv_state *drv)
{
	struct nlattr *cur;
	int rem_combi;
	unsigned int num = 0;
	struct iface_combs *combs;

	if (!combs_attr)
		return -1;

	combs = (struct iface_combs *)
		malloc((num + 1) * sizeof(struct iface_combs));
	if (!combs) {
		hal_printf(MSG_ERROR, "Failed allocation");
		return -1;
	}

	nla_for_each_nested(cur, combs_attr, rem_combi) {
		if (!wiphy_info_parse_single_comb(cur, &combs[num])) {
			combs = (struct iface_combs *)
				realloc((void *)combs,
					(++num) * sizeof(iface_combs));
			if (!combs) {
				hal_printf(MSG_ERROR, "Failed allocation");
				goto fail_combs;
			}
		} else {
			goto fail_combs;
		}
	}

	free(drv->combs);
	drv->combs = combs;
	drv->n_combs = num;

	return 0;
fail_combs:
	free(combs);
	return -1;
}

/**
 * wiphy_info_vendor - get the vendor information
 * @drv - pointer to the driver state
 */
static void wiphy_info_vendor(struct nlattr *vendor, struct drv_state *drv,
			      const char *str)
{
	struct nlattr *nl;
	int rem;

	if (!vendor || !str)
		return;

	nla_for_each_nested(nl, vendor, rem) {
		struct nl80211_vendor_cmd_info *vinfo;
		if (nla_len(nl) != sizeof(*vinfo)) {
			hal_printf(MSG_DEBUG, "Unexpected vendor data info");
			continue;
		}

		vinfo = (struct nl80211_vendor_cmd_info *)nla_data(nl);
		hal_printf(MSG_DEBUG,
			   "Supported vendor %s: vendor_id=0x%x subcmd=%u",
			   str, vinfo->vendor_id, vinfo->subcmd);
	}
}

/**
 * wiphy_get_supported_iftypes - get the supported interface types
 * @attr - the supported interfaces attribute
 * @iftypes - pointer. On return will hold the supported interface types.
 */
static void wiphy_get_supported_iftypes(struct nlattr *attr, u32 *iftypes)
{
	struct nlattr *nl_mode;
	int i;

	if (!attr || !iftypes)
		return;

	nla_for_each_nested(nl_mode, attr, i)
		*iftypes |= BIT(nla_type(nl_mode));

	hal_printf(MSG_DEBUG, "Supported iftypes=0x%X", *iftypes);
}


static int wiphy_info_ftm_init_capa(struct nlattr *capa_attr,
				    struct drv_state *drv)
{
	struct nlattr *tb[NL80211_FTM_CAPA_MAX + 1];

	if (!capa_attr || !drv)
		return -1;

	if (nla_parse_nested(tb, NL80211_FTM_CAPA_MAX, capa_attr, NULL) ||
	    !tb[NL80211_FTM_CAPA_MAX_2_SIDED] ||
	    !tb[NL80211_FTM_CAPA_MAX_TOTAL] ||
	    !tb[NL80211_FTM_CAPA_PREAMBLE] ||
	    !tb[NL80211_FTM_CAPA_BW])
		return -1;

	drv->ftm.max_total = nla_get_u32(tb[NL80211_FTM_CAPA_MAX_TOTAL]);
	drv->ftm.max_2_sided = nla_get_u32(tb[NL80211_FTM_CAPA_MAX_2_SIDED]);

	/* TODO: add more FTM capabs */
	return 0;
}

/**
 * wiphy_info_handler - get the phy information handler
 * @msg - pointer to the response msg
 * @data - pointer to drv_state
 *
 * Process the messages holding the wiphy information and extract
 * the information we need: interface types, supported combinations
 * supported channels etc.
 *
 * Returns NL_SKIP
 */
static int wiphy_info_handler(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh =
		(struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

	drv_state *drv = (struct drv_state *)data;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	/* Supported interface types */
	wiphy_get_supported_iftypes(tb[NL80211_ATTR_SUPPORTED_IFTYPES],
				    &drv->iftypes);

	/* Supported interface combinations and limits*/
	wiphy_info_parse_combs(tb[NL80211_ATTR_INTERFACE_COMBINATIONS],
			       drv);

	/* Supported channels and bands */
	wiphy_info_supported_bands(tb[NL80211_ATTR_WIPHY_BANDS], drv);

	/* Handle supported commands */
	wiphy_info_supp_cmds(tb[NL80211_ATTR_SUPPORTED_COMMANDS], drv);

#ifdef ENABLE_TDLS
	if (tb[NL80211_ATTR_TDLS_SUPPORT])
		drv->tdls_supported = true;
#endif // ENABLE_TDLS

	if (tb[NL80211_ATTR_WIPHY_SELF_MANAGED_REG])
		drv->self_managed_reg = true;

	if (tb[NL80211_ATTR_WIPHY])
		drv->wiphy_idx = nla_get_u32(tb[NL80211_ATTR_WIPHY]);

	wiphy_info_ftm_init_capa(tb[NL80211_ATTR_MSRMENT_FTM_CAPA], drv);

	wiphy_info_vendor(tb[NL80211_ATTR_VENDOR_DATA], drv, "command");
	wiphy_info_vendor(tb[NL80211_ATTR_VENDOR_EVENTS], drv, "event");

	return NL_SKIP;
}


/**
 * wiphy_get_feature_handler - get_supported_features handlers
 * @msg - the received message
 * @arg - pointer to u32 that will hold the supported features.
 *
 * Returns NL_SKIP
 */
static int wiphy_get_feature_handler(struct nl_msg *msg, void *arg)
{
	u32 *features = (u32 *)arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)
		nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES])
		*features = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);

	return NL_SKIP;
}

/**
 * drv_get_protocol_features - get_supported_features.
 * @drv - pointer to the driver state
 *
 * Used mainly to deduce if nl80211 is using split when sending the wiphy
 * info or not.
 * Returns the supported features.
 */
static u32 drv_get_protocol_features(struct drv_state *drv)
{
	struct nl_msg *msg;
	u32 features = 0;

	msg = alloc_nl80211_cmd_msg(drv, 0, NL80211_CMD_GET_PROTOCOL_FEATURES);
	if (!msg)
		return 0;

	if (send_and_recv(drv, msg, wiphy_get_feature_handler, &features))
		return 0;

	return features;
}

static bool is_dump_supported(struct drv_state *drv)
{
	u32 features = drv_get_protocol_features(drv);

	hal_printf(MSG_TRACE, "Protocol features=0x%X", features);

	return (bool)(features & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP);
}

/**
 * drv_get_device_info - get the device information
 * @drv - pointer to the driver state
 *
 * Returns 0 on success, otherwise -1.
 */
static int drv_get_device_info(struct drv_state *drv)
{
	struct nl_msg *msg;

	msg = alloc_nl80211_cmd_msg(drv,
				    is_dump_supported(drv) ? NLM_F_DUMP : 0,
				    NL80211_CMD_GET_WIPHY);
	if (!msg || nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP)) {
		nlmsg_free(msg);
		return -1;
	}

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifidx);

	drv->last_band = 0xFF;

	if (send_and_recv(drv, msg, wiphy_info_handler, (void *)drv))
		return -1;

	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static inline wifi_interface_mode get_ifmode(nl80211_iftype type)
{
	switch(type) {
		case NL80211_IFTYPE_ADHOC:
			return WIFI_INTERFACE_IBSS;
		case NL80211_IFTYPE_STATION:
			return WIFI_INTERFACE_STA;
		case NL80211_IFTYPE_AP:
			return WIFI_INTERFACE_SOFTAP;
		case NL80211_IFTYPE_MESH_POINT:
			return WIFI_INTERFACE_MESH;
		case NL80211_IFTYPE_P2P_CLIENT:
			return WIFI_INTERFACE_P2P_CLIENT;
		case NL80211_IFTYPE_P2P_GO:
			return WIFI_INTERFACE_P2P_GO;
		case NL80211_IFTYPE_UNSPECIFIED:
		default:
			return WIFI_INTERFACE_UNKNOWN;
	}
}

struct drv_if_info {
	u8 *mac_addr;
	enum nl80211_iftype type;
};

static int if_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh =
		(struct genlmsghdr *) nlmsg_data(nlmsg_hdr(msg));
	struct drv_if_info *info = (struct drv_if_info *)arg;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_IFTYPE])
		info->type = (enum nl80211_iftype)nla_get_u32(tb[NL80211_ATTR_IFTYPE]);

	if (tb[NL80211_ATTR_MAC])
		memcpy(info->mac_addr, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);

	return NL_SKIP;
}

int driver_get_interface_info(void *handle, u32 ifidx, u8 addr[ETH_ALEN],
			      wifi_interface_mode *mode)
{
	int ret;
	struct nl_msg *msg;
	struct drv_state *drv = (struct drv_state *)handle;
	struct drv_if_info info = {};

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	msg = alloc_nl80211_cmd_msg(drv, 0, NL80211_CMD_GET_INTERFACE);
	if (!msg)
		return -ENOBUFS;

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);

	info.mac_addr = addr;
	ret = send_and_recv(drv, msg, if_info_handler, &info);
	if (ret)
		hal_printf(MSG_ERROR, "NL80211_CMD_GET_INTERFACE failed err=%d",
			   ret);

	*mode = get_ifmode(info.type);

	return ret;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static void parse_bitrate(struct nlattr *bitrate_attr, u64 *bitrate)
{
	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {};

	rate_policy[NL80211_RATE_INFO_BITRATE].type = NLA_U16;
	rate_policy[NL80211_RATE_INFO_BITRATE32].type = NLA_U32;

	if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
			     bitrate_attr, rate_policy)) {
		hal_printf(MSG_ERROR,
			   "failed to parse nested rate attributes!");
		return;
	}

	if (rinfo[NL80211_RATE_INFO_BITRATE32])
		*bitrate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
	else if (rinfo[NL80211_RATE_INFO_BITRATE])
		*bitrate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
}

static int station_dump(struct nl_msg *msg, struct nlattr **tb,
			struct station_info *sta_info)
{
	struct genlmsghdr *gnlh =
		(struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	/*
	 * Kernel nl80211 uses array of IEEE80211_NUM_TIDS + 2 TIDs statistics
	 * entries. First TID entry is left unused, the rest entries are filled
	 * with per-TID statistics for TIDs 1-16. TID 17 is a special one used
	 * for non-QoS frames statistics
	 */
	struct nlattr *tids[IEEE80211_NUM_TIDS + 2];
	struct nlattr *tid[NL80211_TID_STATS_MAX + 1];
	struct nl80211_sta_flag_update *sta_flags;
	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {};
	static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {};
	u32 flags = 0;
	int i;

	stats_policy[NL80211_STA_INFO_INACTIVE_TIME].type = NLA_U32;
	stats_policy[NL80211_STA_INFO_RX_BYTES64].type = NLA_U64;
	stats_policy[NL80211_STA_INFO_TX_BYTES64].type = NLA_U64;
	stats_policy[NL80211_STA_INFO_RX_PACKETS].type = NLA_U32;
	stats_policy[NL80211_STA_INFO_TX_PACKETS].type = NLA_U32;
	stats_policy[NL80211_STA_INFO_TX_BITRATE].type = NLA_NESTED;
	stats_policy[NL80211_STA_INFO_RX_BITRATE].type = NLA_NESTED;
	stats_policy[NL80211_STA_INFO_TX_RETRIES].type = NLA_U32;
	stats_policy[NL80211_STA_INFO_TX_FAILED].type = NLA_U32;
	stats_policy[NL80211_STA_INFO_SIGNAL_AVG].type = NLA_U8;
	stats_policy[NL80211_STA_INFO_BEACON_SIGNAL_AVG].type = NLA_U8;
	stats_policy[NL80211_STA_INFO_BEACON_RX].type = NLA_U64;

	tid_policy[NL80211_TID_STATS_RX_MSDU].type = NLA_U64;
	tid_policy[NL80211_TID_STATS_TX_MSDU].type = NLA_U64;
	tid_policy[NL80211_TID_STATS_TX_MSDU_RETRIES].type = NLA_U64;
	tid_policy[NL80211_TID_STATS_TX_MSDU_FAILED].type = NLA_U64;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_STA_INFO]) {
		hal_printf(MSG_ERROR, "sta stats missing!");
		return -1;
	}

	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
			     tb[NL80211_ATTR_STA_INFO],
			     stats_policy)) {
		hal_printf(MSG_ERROR, "failed to parse sta info nested attributes!");
		return -1;
	}

	memcpy(sta_info->mac_addr, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);

	if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
		sta_info->rssi_ave =
			nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);
	if (sinfo[NL80211_STA_INFO_TX_BITRATE])
		parse_bitrate(sinfo[NL80211_STA_INFO_TX_BITRATE],
			      &sta_info->tx_bitrate);
	if (sinfo[NL80211_STA_INFO_RX_BITRATE])
		parse_bitrate(sinfo[NL80211_STA_INFO_RX_BITRATE],
			      &sta_info->rx_bitrate);

	if (sinfo[NL80211_STA_INFO_STA_FLAGS]) {
		sta_flags = (struct nl80211_sta_flag_update *)
			    nla_data(sinfo[NL80211_STA_INFO_STA_FLAGS]);

		flags = sta_flags->mask & sta_flags->set;

		if (flags & BIT(NL80211_STA_FLAG_AUTHORIZED))
			sta_info->flags |= BIT(STA_FLAG_AUTHORIZED);

		if (flags & BIT(NL80211_STA_FLAG_AUTHENTICATED))
			sta_info->flags |= BIT(STA_FLAG_AUTHENTICATED);

		if (flags & BIT(NL80211_STA_FLAG_TDLS_PEER))
			sta_info->flags |= BIT(STA_FLAG_TDLS_PEER);
	}

	if (sinfo[NL80211_STA_INFO_BEACON_SIGNAL_AVG])
		sta_info->beacon_rssi_ave =
			nla_get_u8(sinfo[NL80211_STA_INFO_BEACON_SIGNAL_AVG]);

	if (sinfo[NL80211_STA_INFO_BEACON_RX])
		sta_info->beacon_rx =
			nla_get_u64(sinfo[NL80211_STA_INFO_BEACON_RX]);

	if (!sinfo[NL80211_STA_INFO_TID_STATS]) {
		hal_printf(MSG_ERROR, "tid stats missing!");
		return -1;
	}

	if (nla_parse_nested(tids, IEEE80211_NUM_TIDS + 2,
			     sinfo[NL80211_STA_INFO_TID_STATS],
			     NULL)) {
		hal_printf(MSG_ERROR, "failed to parse tid info nested attributes!");
		return -1;
	}

	for (i = 1; i <= IEEE80211_NUM_TIDS + 1; i++) {
		if (nla_parse_nested(tid, NL80211_TID_STATS_MAX, tids[i], tid_policy)) {
			hal_printf(MSG_ERROR, "failed to parse tid info nested attributes!");
			return -1;
		}

		if (tid[NL80211_TID_STATS_RX_MSDU])
			sta_info->tid[i - 1].rx_packets =
				nla_get_u64(tid[NL80211_TID_STATS_RX_MSDU]);
		if (tid[NL80211_TID_STATS_TX_MSDU])
			sta_info->tid[i - 1].tx_packets =
				nla_get_u64(tid[NL80211_TID_STATS_TX_MSDU]);
		if (tid[NL80211_TID_STATS_TX_MSDU_RETRIES])
			sta_info->tid[i - 1].tx_retries =
				nla_get_u64(tid[NL80211_TID_STATS_TX_MSDU_RETRIES]);
		if (tid[NL80211_TID_STATS_TX_MSDU_FAILED])
			sta_info->tid[i - 1].tx_failures =
				nla_get_u64(tid[NL80211_TID_STATS_TX_MSDU_FAILED]);
	}

	return 0;
}

static int station_dump_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct dl_list *sta_list = (struct dl_list *)arg;
	struct station_info *s;

	s = (struct station_info *)zalloc(sizeof(struct station_info));
	if (!s) {
		hal_printf(MSG_ERROR, "%s: Failed to allocate memory", __func__);
		return NL_SKIP;
	}

	if (station_dump(msg, tb, s)) {
		free(s);
		return NL_SKIP;
	}

	dl_list_add_tail(sta_list, &s->list);

	return NL_SKIP;
}

/**
 * driver_get_station_info - obtain station information
 * @handle - pointer to the driver state
 * @ifidx - interface index (wifi_interface_info *)->index
 * @sta_list - stations info list to be filled by the command handler
 * Returns 0 on success, otherwise - negative.
 */
int driver_get_station_info(void *handle, u32 ifidx, struct dl_list *sta_list)
{
	struct drv_state *drv = (struct drv_state *)handle;
	struct nl_msg *msg;
	int ret;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	msg = alloc_nl80211_cmd_msg(drv,
				    is_dump_supported(drv) ? NLM_F_DUMP : 0,
				    NL80211_CMD_GET_STATION);
	if (!msg)
		return -ENOBUFS;

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);

	ret = send_and_recv(drv, msg, station_dump_handler, sta_list);
	if (ret)
		hal_printf(MSG_ERROR, "NL80211_CMD_GET_STATION failed err=%d",
			   ret);

	return ret;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int bss_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {{0}};
	struct dl_list *scan_list = (struct dl_list *)arg;
	struct bss_info *bss_info;
	const u8 *ie = NULL, *beacon_ie = NULL;
	size_t ie_len = 0, beacon_ie_len = 0;

	bss_policy[NL80211_BSS_BSSID].type = NLA_UNSPEC;
	bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
	bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
	bss_policy[NL80211_BSS_INFORMATION_ELEMENTS].type = NLA_UNSPEC;
	bss_policy[NL80211_BSS_BEACON_IES].type = NLA_UNSPEC;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS])
		return NL_SKIP;

	if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
			     bss_policy))
		return NL_SKIP;

	if (!bss[NL80211_BSS_BSSID])
	       return NL_SKIP;

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		ie = (const u8*)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
		ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	}

	if (bss[NL80211_BSS_BEACON_IES]) {
		beacon_ie = (const u8*)nla_data(bss[NL80211_BSS_BEACON_IES]);
		beacon_ie_len = nla_len(bss[NL80211_BSS_BEACON_IES]);
	}

	bss_info = (struct bss_info *)zalloc(sizeof(struct bss_info) + ie_len +
					  beacon_ie_len);
	if (!bss_info) {
		hal_printf(MSG_ERROR, "%s: Failed to allocate memory", __func__);
		return NL_SKIP;
	}

	dl_list_add(scan_list, &bss_info->list);

	memcpy(bss_info->bssid, nla_data(bss[NL80211_BSS_BSSID]), ETH_ALEN);

	if (bss[NL80211_BSS_FREQUENCY])
		bss_info->freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);

	if (bss[NL80211_BSS_CAPABILITY])
		bss_info->capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);

	bss_info->ies_len = ie_len;
	bss_info->beacon_ies_len = beacon_ie_len;
	memcpy(bss_info->ies, ie, ie_len);
	memcpy(bss_info->ies + ie_len, beacon_ie, beacon_ie_len);

	return NL_SKIP;
}

int driver_get_scan_results(void *handle, u32 ifidx, struct dl_list *scan_list)
{
	struct drv_state *drv = (struct drv_state *)handle;
	struct nl_msg *msg;
	int ret;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	msg = alloc_nl80211_cmd_msg(drv,
				    is_dump_supported(drv) ? NLM_F_DUMP : 0,
				    NL80211_CMD_GET_SCAN);
	if (!msg)
		return -ENOBUFS;

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);

	ret = send_and_recv(drv, msg, bss_info_handler, scan_list);
	if (ret){
		hal_printf(MSG_DEBUG, "Scan result fetch failed: ret=%d (%s)",
			   ret, strerror(-ret));
		return ret;
	}

	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int add_survey(struct nl_msg *msg, struct freq_survey *survey)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
	static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {};

	survey_policy[NL80211_ATTR_IFINDEX].type = NLA_U32;
	survey_policy[NL80211_SURVEY_INFO_FREQUENCY].type = NLA_U32;
	survey_policy[NL80211_SURVEY_INFO_NOISE].type = NLA_U8;
	survey_policy[NL80211_SURVEY_INFO_TIME].type = NLA_U64;
	survey_policy[NL80211_SURVEY_INFO_TIME_RX].type = NLA_U64;
	survey_policy[NL80211_SURVEY_INFO_TIME_TX].type = NLA_U64;
	survey_policy[NL80211_SURVEY_INFO_TIME_SCAN].type = NLA_U64;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_IFINDEX]) {
		hal_printf(MSG_ERROR, "Survey data - no ifidx");
		return -1;
	}

	if (!tb[NL80211_ATTR_SURVEY_INFO]) {
		hal_printf(MSG_ERROR, "Survey data - no survey info");
		return -1;
	}

	if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
			     tb[NL80211_ATTR_SURVEY_INFO],
			     survey_policy)) {
		hal_printf(MSG_ERROR, "Survey data - faile to parse survey info");
		return -1;
	}

	survey->ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

	if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
		survey->freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);

	if (sinfo[NL80211_SURVEY_INFO_TIME])
		survey->time_active =
			nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);

	if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
		survey->time_rx =
			nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);

	if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
		survey->time_tx =
			nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);

	if (sinfo[NL80211_SURVEY_INFO_TIME_SCAN])
		survey->time_scan =
			nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_SCAN]);
	return 0;
}

static int survey_handler(struct nl_msg *msg, void *arg)
{
	struct freq_survey *survey;
	struct dl_list *survey_list = (struct dl_list *)arg;

	survey = (struct freq_survey *)zalloc(sizeof(struct freq_survey));
	if  (!survey) {
		hal_printf(MSG_ERROR, "%s: Failed to allocate memory", __func__);
		return NL_SKIP;
	}

	if (add_survey(msg, survey)) {
		free(survey);
		return NL_SKIP;
	}

	dl_list_add_tail(survey_list, &survey->list);

	return NL_SKIP;
}

int driver_get_survey(void *handle, u32 ifidx, struct dl_list *survey_list)
{
	struct drv_state *drv = (struct drv_state *)handle;
	struct nl_msg *msg;
	int ret;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	msg = alloc_nl80211_cmd_msg(drv,
				    is_dump_supported(drv) ? NLM_F_DUMP : 0,
				    NL80211_CMD_GET_SURVEY);
	if (!msg)
		return -ENOBUFS;

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);
	NLA_PUT_U8(msg, NL80211_ATTR_SURVEY_RADIO_STATS, 1);

	hal_printf(MSG_TRACE, "Fetch survey data");
	ret = send_and_recv(drv, msg, survey_handler, survey_list);
	if (ret) {
		hal_printf(MSG_ERROR, "Failed to process survey data: err = %d", ret);
		return ret;
	}

	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static struct nlattr *parse_vendor_reply(struct nl_msg *msg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)
		nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	genlmsg_attrlen(gnlh, 0), NULL);
	return tb[NL80211_ATTR_VENDOR_DATA];
}

static void drv_del_station_event(struct drv_state *drv, struct nl_msg *msg,
				  struct nlattr **tb)
{
	struct station_info sta_info = {{0}};
	u32 ifidx;

	if (!tb[NL80211_ATTR_IFINDEX])
		return;

	ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

	if (!station_dump(msg, tb, &sta_info))
		drv->event_cb(drv->handle, ifidx, DRV_EVENT_DEL_STATION, &sta_info);
}

static void drv_connect_event(struct drv_state *drv, struct nl_msg *msg,
			      struct nlattr **tb)
{
	u32 ifidx;
	u16 status;

	if (!tb[NL80211_ATTR_IFINDEX] || !tb[NL80211_ATTR_STATUS_CODE])
		return;

	ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
	status = nla_get_u16(tb[NL80211_ATTR_STATUS_CODE]);

	hal_printf(MSG_DEBUG, "Connection result: %d", status);
	if (!status)
		drv->event_cb(drv->handle, ifidx, DRV_EVENT_CONNECT, NULL);
}

static int nl80211_process_event(struct nl_msg *msg, void *arg)
{
	struct drv_state *drv = (struct drv_state *)arg;
	struct genlmsghdr *gnlh = (struct genlmsghdr *)
		nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	hal_printf(MSG_DEBUG, "Drv Event %d received", gnlh->cmd);

	switch (gnlh->cmd) {
	case NL80211_CMD_VENDOR:
		drv_vendor_event(drv, tb);
		break;
	case NL80211_CMD_DEL_STATION:
		drv_del_station_event(drv, msg, tb);
		break;
	case NL80211_CMD_CONNECT:
		drv_connect_event(drv, msg, tb);
		break;
	default:
		break;
	}

	return NL_SKIP;
}

/**
 * drv_check_info - check we have all the info needed to start.
 * @drv - pointer to the driver state
 *
 * Return 0 if all the information needed for proper functionality
 * is available, otherwise return -1.
 */
static int drv_check_info(struct drv_state *drv)
{
	hal_printf(MSG_DEBUG, "Iftypes=0x%X, n_combs=%u, n_bands=%u",
		   drv->iftypes, drv->n_combs, drv->n_bands);

	if (!drv->iftypes && (!drv->combs || !drv->n_combs)) {
		hal_printf(MSG_ERROR, "No supported interface types");
		return -1;
	}

	if (!drv->bands || !drv->n_bands) {
		hal_printf(MSG_ERROR, "No supported interface bands");
		return -1;
	}

	return 0;
}

/**
 * drv_cleanp - cleanup the driver state
 * @drv - pointer to the driver state
 */
static void drv_cleanup(struct drv_state *drv)
{
	u32 idx;

	if (MUTEX_LOCK(&drv->sync))
		return;

	drv->in_cleanup = 1;
	if (!drv->event_thread) {
		MUTEX_UNLOCK(&drv->sync);
		goto complete_cleanup;
	}

	MUTEX_UNLOCK(&drv->sync);

	while (drv->event_thread) {
		pthread_kill(drv->event_thread, SIGUSR1);

		hal_printf(MSG_DEBUG, "Pending event loop");
		usleep(10000);
	}

complete_cleanup:
	for (idx = 0; idx < drv->n_bands; idx++)
		free(drv->bands[idx].channels);

	free(drv->bands);
	free(drv->combs);

	nl_cb_put(drv->nl_cb);
	nl_socket_free(drv->nl_sock);
	nl_socket_free(drv->nl_event);
	pthread_mutex_destroy(&drv->sync);

	memset(drv, 0, sizeof(*drv));
}

void *driver_if_init(void *handle, drv_event_cb event_cb, u32 ifidx)
{
	struct drv_state *drv;

	drv = (struct drv_state *)zalloc(sizeof(drv_state));

	if (!drv) {
		hal_printf(MSG_ERROR, "Failed to allocate driver");
		return NULL;
	}

	hal_printf(MSG_DEBUG, "%s: ifidx=%u", __func__, ifidx);

	drv->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!drv->nl_cb) {
		hal_printf(MSG_ERROR, "Failed to allocate netlink callback!");
		free(drv);
		return NULL;
	}

	nl_cb_set(drv->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
		  no_seq_check, NULL);

	nl_cb_set(drv->nl_cb, NL_CB_VALID, NL_CB_CUSTOM,
		  nl80211_process_event, drv);

	if (nl80211_init_socket(&drv->nl_sock, drv->nl_cb))
		goto out_cb_destroy;

	drv->nl80211_id = genl_ctrl_resolve(drv->nl_sock, NL80211_GENL_NAME);
	if (drv->nl80211_id < 0) {
		hal_printf(MSG_ERROR, "nl80211 not found!");
		goto out_socket_destroy;
	}

	if (nl80211_init_socket(&drv->nl_event, drv->nl_cb))
		goto out_socket_destroy;

	if (nl80211_mc_groups(drv) < 0)
		goto out_socket_destroy;

	drv->ifidx = ifidx;
	drv->handle = handle;
	drv->event_cb = event_cb;
	drv->wiphy_idx = -1;
	if (drv_get_device_info(drv) < 0) {
		hal_printf(MSG_ERROR, "Failed to get device information");
		goto out_socket_destroy;
	}

	if (drv_check_info(drv) < 0) {
		drv_cleanup(drv);
		free(drv);
		return NULL;
	}

	pthread_mutex_init(&drv->sync, NULL);
	dl_list_init(&drv->ftm.cur_response);
	drv->initialized = true;

	hal_printf(MSG_DEBUG, "Succesfully initialized driver interface");
	return drv;

out_socket_destroy:
	nl_socket_free(drv->nl_sock);
	nl_socket_free(drv->nl_event);
out_cb_destroy:
	nl_cb_put(drv->nl_cb);
	free(drv);
	return NULL;
}

void driver_if_deinit(void *handle)
{
	struct drv_state *drv = (struct drv_state *)handle;

	if (DRV_NOT_INIT(drv, __func__))
		return;

	drv_cleanup(drv);
	free(drv);
}

static u8 drv_sta_sta_allowed(struct iface_combs *comb)
{
	u32 sta_sta, i;

	/* No concurrency allowed */
	if (comb->n_ifaces <= 1)
		return 0;

	for (sta_sta = 0, i = 0; i < comb->n_limits; i++) {
		const struct iface_limits *l = &comb->limits[i];

		if (l->types & BIT(NL80211_IFTYPE_STATION))
			sta_sta += l->max;

		if (sta_sta >= 2)
			return 1;
	}
	return 0;
}

static u8 drv_sta_ap_allowed(struct iface_combs *comb)
{
	u32 sta_ap, i;

	/* No concurrency allowed */
	if (comb->n_ifaces <= 1)
		return 0;

	for (sta_ap = 0, i = 0; i < comb->n_limits; i++) {
		const struct iface_limits *l = &comb->limits[i];

		if (l->types & BIT(NL80211_IFTYPE_STATION)) {
			sta_ap |= 0x1;

			/* This limit also supports AP mode */
			if (l->types & BIT(NL80211_IFTYPE_AP)) {
				/* Limit support multi interfaces */
				if (l->max >= 2)
					return 1;
				else
					sta_ap |= 0x2;
			}
		} else if (l->types & BIT(NL80211_IFTYPE_AP)) {
			sta_ap |= 0x2;
		}

		if (sta_ap == 0x3)
			return 1;
	}
	return 0;
}

feature_set driver_if_get_feature_set(void *handle)
{
	struct drv_state *drv = (struct drv_state *)handle;
	feature_set fs;
	u32 i;

	if (DRV_NOT_INIT(drv, __func__))
		return 0;

	hal_printf(MSG_DEBUG, "Supported iftypes=0x%X", drv->iftypes);

	fs = 0;
	if (drv->iftypes & BIT(NL80211_IFTYPE_STATION)) {
		u32 i;

		fs |= WIFI_FEATURE_INFRA;
		for (i = 0; i < drv->n_bands; i++)
			if (drv->bands[i].band == NL80211_BAND_5GHZ)
				fs |= WIFI_FEATURE_INFRA_5G;
#ifdef ENABLE_PASSPOINT
		/* With all latest hostap version, if station is supported, also
		 * offchannel is supported so hotspot is also supported.
		 */
		fs |= WIFI_FEATURE_HOTSPOT;
#endif // ENABLE_PASSPOINT
	}

	if (drv->iftypes & BIT(NL80211_IFTYPE_AP))
		fs |= WIFI_FEATURE_SOFT_AP;

	if (drv->iftypes & BIT(NL80211_IFTYPE_P2P_DEVICE) &&
	    (drv->iftypes & BIT(NL80211_IFTYPE_P2P_CLIENT) ||
	     drv->iftypes & BIT(NL80211_IFTYPE_P2P_GO)))
		fs |= WIFI_FEATURE_P2P;

	if (drv->pno_supported)
		fs |= WIFI_FEATURE_PNO;

#ifdef ENABLE_TDLS
	if (drv->tdls_supported)
		fs |= WIFI_FEATURE_TDLS;
#endif // ENABLE_TDLS

	/* Check about STA + STA and STA + AP */
	for (i = 0; i < drv->n_combs; i++) {
		struct iface_combs *comb = &drv->combs[i];

		if (drv_sta_sta_allowed(comb))
			fs |= WIFI_FEATURE_ADDITIONAL_STA;

		if (drv_sta_ap_allowed(comb))
			fs |= WIFI_FEATURE_AP_STA;
	}

	hal_printf(MSG_DEBUG, "Supported features=0x%X", fs);
	return fs;
}

int driver_get_channels(void *handle, wifi_band band, int *size,
			wifi_channel *list)
{
	struct drv_state *drv = (struct drv_state *)handle;
	u32 i, j;
	int k;

	if (DRV_NOT_INIT(drv, __func__))
		return 0;

	hal_printf(MSG_ERROR, "get_channels band=%u, size=%d", band, *size);

	memset(list, 0, sizeof(wifi_channel) * (*size));
	for (i = 0, k = 0; i < drv->n_bands; i++) {
		struct band_info *curb = &drv->bands[i];

		/* skip 2.4 channels if not requested */
		if (curb->band == NL80211_BAND_2GHZ &&
		    (band == WIFI_BAND_A || band == WIFI_BAND_A_DFS ||
		     band == WIFI_BAND_A_WITH_DFS))
			continue;

		/* skip 5.2 channels if not requested */
		if (curb->band == NL80211_BAND_5GHZ && band == WIFI_BAND_BG)
			continue;

		for (j = 0; j < curb->n_channels; j++) {
			channel_info *curc = &curb->channels[j];

			if (curc->flags & CHAN_FLAG_DISABLED)
				continue;

			/* Skip DFS channels if not requested */
			if (curc->flags & CHAN_FLAG_RADAR &&
			    band != WIFI_BAND_A_DFS &&
			    band != WIFI_BAND_A_WITH_DFS &&
			    band != WIFI_BAND_ABG_WITH_DFS &&
			    band != WIFI_BAND_UNSPECIFIED)
				continue;

			/* Skip non DFS channels if only DFS requested */
			if (!(curc->flags & CHAN_FLAG_RADAR) &&
			    band == WIFI_BAND_A_DFS)
				continue;

			list[k] = curc->freq;

			if (++k == *size)
				goto out;
		}
	}

out:
	hal_printf(MSG_DEBUG, "Num reported channels=%u", k);
	*size = k;
	return 0;
}

static int get_country_handler(struct nl_msg *msg, void *arg)
{
	char *code = (char *)arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)
		nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb_msg[NL80211_ATTR_REG_ALPHA2]) {
		hal_printf(MSG_DEBUG, "nl80211: No country information available");
		return NL_SKIP;
	}

	memcpy(code, nla_data(tb_msg[NL80211_ATTR_REG_ALPHA2]), 2);
	return NL_SKIP;
}

int driver_get_country_code(void *handle, char *code)
{
	struct nl_msg *msg;
	int ret = -ENOBUFS;
	struct drv_state *drv = (struct drv_state *)handle;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	msg = alloc_nl80211_cmd_msg(drv, 0, NL80211_CMD_GET_REG);
	if (!msg)
		return -ENOBUFS;

	if (drv->wiphy_idx > 0 && drv->self_managed_reg)
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, drv->wiphy_idx);

	code[0] = '\0';
	ret = send_and_recv(drv, msg, get_country_handler, code);
	if (!code)
		ret = -EINVAL;

	return ret;
nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int get_fw_version_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *cap[MAX_IWL_MVM_VENDOR_ATTR + 1];
	static struct nla_policy attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {};
	char *code = (char *)arg;

	struct nlattr *data = parse_vendor_reply(msg);
	if (!data)
	    return NL_SKIP;

	attr_policy[IWL_MVM_VENDOR_ATTR_FW_VER].type = NLA_STRING;

	if (nla_parse_nested(cap, MAX_IWL_MVM_VENDOR_ATTR,
	    data, attr_policy)) {
		hal_printf(MSG_WARNING, "Failed to get fw version");
		return NL_SKIP;
	}
	if (!cap[IWL_MVM_VENDOR_ATTR_FW_VER]) {
	    hal_printf(MSG_DEBUG, "nl80211: F/w version unavailable");
	    return NL_SKIP;
	}

	//copy attribute to a sized string
	nla_strlcpy(code, cap[IWL_MVM_VENDOR_ATTR_FW_VER],
		    DRV_FW_VERSION_MAX_LEN);
	return NL_SKIP;
}


int driver_get_fw_version(void *handle, char *buf, int buf_size)
{
	int ret;
	struct drv_state *drv = (struct drv_state *)handle;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	buf[0] = '\0';

	ret = drv_vendor_cmd(drv, IWL_MVM_VENDOR_CMD_GET_FW_VERSION,
			     NULL, 0, 0, get_fw_version_handler, buf);
	if (!buf)
		ret = -EINVAL;

	return ret;
}

static int get_drv_version_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *cap[MAX_IWL_MVM_VENDOR_ATTR + 1];
	static struct nla_policy attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {};
        char *code = (char *)arg;

	struct nlattr *data = parse_vendor_reply(msg);
	if (!data)
	    return NL_SKIP;

	attr_policy[IWL_MVM_VENDOR_ATTR_DRV_VER].type = NLA_STRING;

	if (nla_parse_nested(cap, MAX_IWL_MVM_VENDOR_ATTR, data, attr_policy)) {
		hal_printf(MSG_WARNING, "Failed to get driver version");
		return NL_SKIP;
	}

	if (!cap[IWL_MVM_VENDOR_ATTR_DRV_VER]) {
		hal_printf(MSG_DEBUG, "nl80211: Driver version unavailable");
		return NL_SKIP;
	}
	//copy attribute to a sized string
	nla_strlcpy(code, cap[IWL_MVM_VENDOR_ATTR_DRV_VER],
		    DRV_FW_VERSION_MAX_LEN);
	return NL_SKIP;
}


int driver_get_drv_version(void *handle, char *buf, int buf_size)
{
	int ret;
	struct drv_state *drv = (struct drv_state *)handle;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	buf[0] = '\0';

	ret = drv_vendor_cmd(drv, IWL_MVM_VENDOR_CMD_GET_DRV_VERSION,
			     NULL, 0, 0, get_drv_version_handler, buf);
	if (!buf)
	    ret = -EINVAL;

	return ret;
}

int driver_set_country_code(void *handle, const char *code)
{
	struct nl_msg *msg;
	int ret;
	struct drv_state *drv = (struct drv_state *)handle;

	if (DRV_NOT_INIT(drv, __func__))
		return -ENODEV;

	msg = alloc_nl80211_cmd_msg(drv, 0, NL80211_CMD_REQ_SET_REG);
	if (!msg)
		return -ENOBUFS;

	if (nla_put(msg, NL80211_ATTR_REG_ALPHA2, 2, (const u8 *)code)) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	ret = send_and_recv(drv, msg, 0, 0);

	if (ret)
		hal_printf(MSG_ERROR, "Failed to set country code: err = %d (self-managed=%d)",
			   ret, drv->self_managed_reg);
	return ret;
}

static void event_handler_sock(struct nl_sock *sock)
{
	struct nl_cb *cb = NULL;
	
	if (sock != NULL) {
		cb = nl_socket_get_cb(sock);

		if (nl_recvmsgs(sock, cb) < 0)
			hal_printf(MSG_ERROR, "Error receiving event res");

		nl_cb_put(cb);
	}
}

static void drv_sigusr1(int i)
{
}

#define NFDS 2
void driver_if_events(void *handle)
{
	struct drv_state *drv = (struct drv_state *)handle;
	pollfd pfd[NFDS];
	sigset_t sms;
	struct timespec ts = {DRV_POLL_TIMEOUT_SEC, 0};
	int i, ret;

	if (DRV_NOT_INIT(drv, __func__))
		return;

	if (drv->event_thread) {
		hal_printf(MSG_ERROR, "%s called when already on event loop",
			   __func__);
		return;
	}

	if (MUTEX_LOCK(&drv->sync))
		return;

	if (drv->in_cleanup) {
		hal_printf(MSG_ERROR, "In cleanup. Cannot start event loop");
		MUTEX_UNLOCK(&drv->sync);
		return;
	}
	drv->event_thread = pthread_self();
	MUTEX_UNLOCK(&drv->sync);

	pfd[0].fd = nl_socket_get_fd(drv->nl_event);
	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;

	ret = pthread_sigmask(SIG_BLOCK, NULL, &sms);
	ret |= sigdelset(&sms, SIGUSR1);
	if (ret) {
		hal_printf(MSG_ERROR, "Fail to operate thread signal mask");
		return;
	}

	if (signal(SIGUSR1, drv_sigusr1) == SIG_ERR) {
		hal_printf(MSG_ERROR, "Fail to change SIGUSR1 handler");
		return;
	}

	hal_printf(MSG_DEBUG, "Starting event loop tid=%u",
		   drv->event_thread);

	while (!drv->in_cleanup) {
		pfd[1].fd = drv->nl_rtt ? nl_socket_get_fd(drv->nl_rtt) : -1;
		int res = ppoll(pfd, NFDS, &ts, &sms);
		hal_printf(MSG_ERROR, "Out of event poll");

		if (res < 0 && errno != EINTR) {
			hal_printf(MSG_ERROR,
				   "Error event socket res=%d, errno=%d", res, errno);
		} else if (res == 0) {
			hal_printf(MSG_ERROR, "Timeout on event socket");
		} else {
			for (i = 0; i < NFDS; i++) {
				if (pfd[i].revents & POLLERR) {
					char buf[64];

					hal_printf(MSG_ERROR,
						   "Error condition on event socket %d",
						   i);

					res = read(pfd[i].fd, buf, sizeof(buf));
					if (res < 0) {
						hal_printf(MSG_ERROR,
					          "Failed reading from socket");
						break;
					}
				} else if (pfd[i].revents & POLLHUP) {
					hal_printf(MSG_ERROR,
						   "event socket %d closed", i);
					break;
				} else if (pfd[i].revents & POLLIN) {
					hal_printf(MSG_DEBUG,
						   "Data on event socket %d", i);
					event_handler_sock(i == 0 ?
							   drv->nl_event :
							   drv->nl_rtt);
				} else {
					hal_printf(MSG_TRACE,
						   "Event socket %d revent=0x%X",
						   i, pfd[i].revents);
				}
			}
		}
	}

	MUTEX_LOCK(&drv->sync);

	drv->event_thread = 0;

	MUTEX_UNLOCK(&drv->sync);

	signal(SIGUSR1, SIG_DFL);
	hal_printf(MSG_DEBUG, "Out of event loop");
}

