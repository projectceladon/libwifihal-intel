/*
 * IEEE 802.11 Frame type definitions
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 * Copyright(c) 2013 - 2014 Intel Mobile Communications GmbH.
 * Copyright(c) 2011 - 2014 Intel Corporation. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_11_DEFS_H
#define IEEE802_11_DEFS_H

#include "common.h"

/* IEEE 802.11 defines */

/* Information Element IDs */
#define WLAN_EID_SSID 0
#define WLAN_EID_SUPP_RATES 1
#define WLAN_EID_FH_PARAMS 2
#define WLAN_EID_DS_PARAMS 3
#define WLAN_EID_CF_PARAMS 4
#define WLAN_EID_TIM 5
#define WLAN_EID_IBSS_PARAMS 6
#define WLAN_EID_COUNTRY 7
#define WLAN_EID_BSS_LOAD 11
#define WLAN_EID_CHALLENGE 16
/* EIDs defined by IEEE 802.11h - START */
#define WLAN_EID_PWR_CONSTRAINT 32
#define WLAN_EID_PWR_CAPABILITY 33
#define WLAN_EID_TPC_REQUEST 34
#define WLAN_EID_TPC_REPORT 35
#define WLAN_EID_SUPPORTED_CHANNELS 36
#define WLAN_EID_CHANNEL_SWITCH 37
#define WLAN_EID_MEASURE_REQUEST 38
#define WLAN_EID_MEASURE_REPORT 39
#define WLAN_EID_QUITE 40
#define WLAN_EID_IBSS_DFS 41
/* EIDs defined by IEEE 802.11h - END */
#define WLAN_EID_ERP_INFO 42
#define WLAN_EID_HT_CAP 45
#define WLAN_EID_QOS 46
#define WLAN_EID_RSN 48
#define WLAN_EID_EXT_SUPP_RATES 50
#define WLAN_EID_NEIGHBOR_REPORT 52
#define WLAN_EID_MOBILITY_DOMAIN 54
#define WLAN_EID_FAST_BSS_TRANSITION 55
#define WLAN_EID_TIMEOUT_INTERVAL 56
#define WLAN_EID_RIC_DATA 57
#define WLAN_EID_SUPPORTED_OPERATING_CLASSES 59
#define WLAN_EID_EXT_CHANSWITCH_ANN 60
#define WLAN_EID_HT_OPERATION 61
#define WLAN_EID_SECONDARY_CHANNEL_OFFSET 62
#define WLAN_EID_WAPI 68
#define WLAN_EID_TIME_ADVERTISEMENT 69
#define WLAN_EID_RRM_ENABLED_CAPABILITIES 70
#define WLAN_EID_20_40_BSS_COEXISTENCE 72
#define WLAN_EID_20_40_BSS_INTOLERANT 73
#define WLAN_EID_OVERLAPPING_BSS_SCAN_PARAMS 74
#define WLAN_EID_MMIE 76
#define WLAN_EID_SSID_LIST 84
#define WLAN_EID_BSS_MAX_IDLE_PERIOD 90
#define WLAN_EID_TFS_REQ 91
#define WLAN_EID_TFS_RESP 92
#define WLAN_EID_WNMSLEEP 93
#define WLAN_EID_TIME_ZONE 98
#define WLAN_EID_LINK_ID 101
#define WLAN_EID_INTERWORKING 107
#define WLAN_EID_ADV_PROTO 108
#define WLAN_EID_QOS_MAP_SET 110
#define WLAN_EID_ROAMING_CONSORTIUM 111
#define WLAN_EID_EXT_CAPAB 127
#define WLAN_EID_CCKM 156
#define WLAN_EID_VHT_CAP 191
#define WLAN_EID_VHT_OPERATION 192
#define WLAN_EID_VHT_EXTENDED_BSS_LOAD 193
#define WLAN_EID_VHT_WIDE_BW_CHSWITCH  194
#define WLAN_EID_VHT_TRANSMIT_POWER_ENVELOPE 195
#define WLAN_EID_VHT_CHANNEL_SWITCH_WRAPPER 196
#define WLAN_EID_VHT_AID 197
#define WLAN_EID_VHT_QUIET_CHANNEL 198
#define WLAN_EID_VHT_OPERATING_MODE_NOTIFICATION 199
#define WLAN_EID_VENDOR_SPECIFIC 221

#define OUI_MICROSOFT 0x0050f2 /* Microsoft (also used in Wi-Fi specs)
				* 00:50:F2 */
#define WPA_IE_VENDOR_TYPE 0x0050f201
#define WMM_IE_VENDOR_TYPE 0x0050f202
#define WPS_IE_VENDOR_TYPE 0x0050f204
#define OUI_WFA 0x506f9a
#define P2P_IE_VENDOR_TYPE 0x506f9a09
#define WFD_IE_VENDOR_TYPE 0x506f9a0a
#define WFD_OUI_TYPE 10
#define HS20_IE_VENDOR_TYPE 0x506f9a10
#define OSEN_IE_VENDOR_TYPE 0x506f9a12

#define WMM_OUI_TYPE 2
#define WMM_OUI_SUBTYPE_INFORMATION_ELEMENT 0
#define WMM_OUI_SUBTYPE_PARAMETER_ELEMENT 1
#define WMM_OUI_SUBTYPE_TSPEC_ELEMENT 2
#define WMM_VERSION 1

#define WLAN_CAPABILITY_PRIVACY		(1<<4)
#define WLAN_CAPABILITY_DMG_PRIVACY	(1<<4)

struct wlan_ie {
	u8 eid;
	u8 length;
} STRUCT_PACKED;

struct vendor_ie {
	struct wlan_ie hdr;
	union vendor_type {
		struct vendor_oui {
			u8 oui[3];
			u8 oui_type;
		} STRUCT_PACKED oui;
		be32 id;
	} STRUCT_PACKED vendor;
	u8 oui_subtype;
} STRUCT_PACKED;

#define IS_VENDOR_TYPE(ie, vendor_id) (((struct vendor_ie *)(ie))->hdr.eid == \
		       WLAN_EID_VENDOR_SPECIFIC && \
		       be_to_host32(((struct vendor_ie *)(ie))->vendor.id)\
		       == (vendor_id))

#define IEEE80211_NUM_TIDS              16

#define IEEE80211_MAX_SSID_LEN		32

struct ieee80211_mgmt {
	le16 frame_control;
	le16 duration;
	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	le16 seq_ctrl;
	union {
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* Followed by some of SSID, Supported rates,
			 * FH params, DS params, CF params, IBSS params, TIM */
			u8 variable[];
		} STRUCT_PACKED beacon;
		/* TODO: Add more mgmt frame types */
	} u;
} STRUCT_PACKED;

#endif /* IEEE802_11_DEFS_H */
