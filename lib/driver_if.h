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

#ifndef __DRIVER_IF_H__
#define __DRIVER_IF_H__

#ifdef ANDROID
#include <wifi_hal.h>
#else
#include "wifi_hal.h"
#endif
#include "ieee802_11_defs.h"
#include "utils.h"

#define DRV_FW_VERSION_MAX_LEN 50

enum drv_event {
	DRV_EVENT_DEL_STATION,
	DRV_EVENT_CONNECT,

	DRV_EVENT_INVALID = -1
};

/*
 * Driver event callback type. The driver layer is separated from the rest of
 * the Wifi HAL. This event callback resides in the HAL and is called by the
 * driver when kernel event occurs.
 * @handle (void *) - HAL's context handle
 * @ifidx (u32) - interface index
 * @event (enum drv_event) - kernel event
 * @data (void *) - event specific data
 */
typedef int(*drv_event_cb)(void *, u32, enum drv_event, void *);

enum station_flags {
	STA_FLAG_AUTHORIZED,
	STA_FLAG_AUTHENTICATED,
	STA_FLAG_TDLS_PEER,
};

/* struct station_tid_info - contains TID specific data used for
 * statistics report in wifi_wmm_ac_stat.
 * @rx_packets: total packets recieved from this station
 * @tx_packets: total packets transmited to this station
 * @tx_retries: total retries to this station
 * @tx_failures: total failed packets to this station
 */
struct station_tid_info {
	u64 rx_packets;
	u64 tx_packets;
	u64 tx_retries;
	u64 tx_failures;
};

/*
 * struct station_info - contains peer data used for statistics report in
 * wifi_peer_info and wifi_iface_state.
 * @list: linked list reference
 * @mac_addr: peer's MAC address
 * @rssi_ave: signal strength average
 * @beacon_rssi_ave: signal strength average measured only from beacons
 * @rx_bitrate: last unicast rx packet's rate
 * @tx_bitrate: current unicast tx rate
 * @tid: TID specific data
 * @flags: enum station_flags
 * @beacon_rx: number of recieved beacons (BSS station mode only)
 */
struct station_info {
	struct dl_list list;
	u8 mac_addr[ETH_ALEN];
	s8 rssi_ave;
	s8 beacon_rssi_ave;
	u64 rx_bitrate;
	u64 tx_bitrate;
	struct station_tid_info tid[IEEE80211_NUM_TIDS + 1];
	int flags;
	u64 beacon_rx;
};

/*
 * struct bss_info - BSS information obtained from scan results
 * @freq - BSS operating frequency
 * @capa - BSS capabilities bitmap as defined in IEEE 802.11
 * @ies_len - length of IEs list
 * @beacon_ies_len - length of IEs list containing Beacon IEs
 * @ies - this can include two IEs lists placed in sequence
 */
struct bss_info {
	struct dl_list list;
	u8 bssid[ETH_ALEN];
	u32 freq;
	u16 capa;
	size_t ies_len;
	size_t beacon_ies_len;
	u8 ies[];
};

/**
 * struct freq_survey - Channel survey info
 *
 * The survey info is retrieved by means of GET_SURVEY command. The obtained
 * data is either per channel or global. These values are obtained from the
 * device firmware. They are never reset, so the Wifi HAL handles the case when
 * statistics reset is requested.
 *
 * @list: Internal list pointers
 * @ifidx: Interface index in which this survey was observed
 * @freq: Center of frequency of the surveyed channel
 * @time_active: Amount of time in ms the radio was on
 * @time_rx: amount of time in ms the radio spent receiving data
 * @time_tx: amount of time in ms the radio spent transmitting data
 * @time_scan: amount of time in ms the radio spent scanning
 */
struct freq_survey {
	struct dl_list list;
	u32 ifidx;
	u32 freq;
	u64 time_active;
	u64 time_rx;
	u64 time_tx;
	u64 time_scan;
};

void *driver_if_init(void *handle, drv_event_cb event_cb, u32 ifidx);
void driver_if_deinit(void *handle);
feature_set driver_if_get_feature_set(void *handle);
int driver_get_channels(void *handle, wifi_band band, int *size,
			wifi_channel *list);
void driver_if_events(void *handle);
int driver_get_interface_info(void *handle, u32 if_idx, u8 addr[ETH_ALEN],
			      wifi_interface_mode *mode);
int driver_get_station_info(void *handle, u32 ifidx,
			    struct dl_list *stations_list);
int driver_get_scan_results(void *handle, u32 ifidx, struct dl_list *scan_list);
int driver_get_survey(void *handle, u32 ifidx, struct dl_list *survey_list);

int driver_set_country_code(void *handle, const char *code);
int driver_get_country_code(void *handle, char *code);
int driver_get_fw_version(void *handle, char *buffer, int buffer_size);
int driver_get_drv_version(void *handle, char *buffer, int buffer_size);
#endif /* __DRIVER_IF_H__ */
