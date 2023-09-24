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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>

#include "wifi_hal_ext.h"
#include "hal_debug.h"
#include "driver_if.h"
#include "utils.h"

#define WIFI_INFO_MAGIC 0xDBADBADA

#define WIFI_INFO_INVALID(_handle, _str) ({                                    \
	int ret = !!(!_handle || _handle->magic != WIFI_INFO_MAGIC);           \
	if (ret)                                                               \
		hal_printf(MSG_ERROR, "%s called with invalid handle", _str);  \
	(ret);                                                                 \
})

static int is_wifi_iface(char *name)
{
	return (strncmp(name, "wlan", 4) == 0 ||
		strncmp(name, "p2p-p2p", 7) == 0);
}

static int if_handle_read(wifi_interface_handle *info,
			  const char *name)
{
	(*info) = (wifi_interface_info *)zalloc(sizeof(wifi_interface_info));
	if (!(*info)) {
		hal_printf(MSG_WARNING, "Failed to allocate interface");
		return -1;
	}

	(*info)->index = if_nametoindex(name);
	if (!(*info)->index) {
		hal_printf(MSG_ERROR, "Unable to get %s index!", name);
		free(*info);
		return -1;
	}

	strncpy((*info)->name, name, IF_NAMESIZE);
	(*info)->magic = WIFI_INFO_MAGIC;
	hal_printf(MSG_DEBUG, "Interface %s initialized, index = %d",
		   (*info)->name, (*info)->index);

	return 0;
}

void handle_if_init(wifi_handle handle)
{
	struct dirent *de;
	int num_ifaces = 0, i = 0;
	const char *dir = "/sys/class/net";

	DIR *d = opendir(dir);
	if (!d) {
		hal_printf(MSG_ERROR, "Unable to open interface directory!");
		return;
	}

	while ((de = readdir(d))) {
		if (is_wifi_iface(de->d_name))
			num_ifaces++;
	}

	if (!num_ifaces)
		goto out;

	rewinddir(d);
	if (!d) {
		hal_printf(MSG_ERROR, "Unable to rewind interface directory!");
		goto out;
	}

	handle->ifaces = (wifi_interface_handle *)
		malloc(sizeof(wifi_interface_handle) * num_ifaces);

	if (!handle->ifaces) {
		hal_printf(MSG_ERROR, "Failed to allocate interfaces!");
		goto out;
	}

	while ((de = readdir(d)) && i < num_ifaces) {
		if (is_wifi_iface(de->d_name)) {
			if (if_handle_read(&handle->ifaces[i], de->d_name) < 0) {
				i = 0;
				free(handle->ifaces);
				goto out;
			}

			handle->ifaces[i]->handle = handle;
			i++;
		}
	}

out:
	closedir(d);
	handle->num_ifaces = i;
}

static void handle_if_deinit(wifi_handle handle)
{
	u32 i;

	for (i = 0; i < handle->num_ifaces; i++) {
		handle->ifaces[i]->magic = 0xFFFFFFFF;
		free(handle->ifaces[i]);
	}

	free(handle->ifaces);
}

static int wifi_drv_event_cb(void *w_handle, u32 ifidx, enum drv_event event,
			     void *data)
{
	int ret;
	u32 i;
	struct wifi_interface_info *iface = NULL;
	wifi_handle handle = (wifi_handle)w_handle;

	for (i = 0; i < handle->num_ifaces; i++) {
		if (handle->ifaces[i]->index == ifidx) {
			iface = handle->ifaces[i];
			break;
		}
	}

	switch(event) {
		default:
			hal_printf(MSG_ERROR, "Not supported event: %d", event);
			ret = -1;
	}

	return ret;
}

wifi_error wifi_initialize(wifi_handle *phandle)
{
	u32 i;

	hal_debug_open_syslog();

	hal_printf(MSG_DEBUG, "Initialize wifi HAL");

	if (!phandle) {
		hal_printf(MSG_ERROR, "Invalid handle pointer");
		hal_debug_close_syslog();
		return WIFI_ERROR_UNINITIALIZED;
	}

	*phandle = (wifi_handle)zalloc(sizeof(struct wifi_info));
	if (!*phandle) {
		hal_printf(MSG_ERROR, "Failed to allocate wifi handle");
		return WIFI_ERROR_OUT_OF_MEMORY;
	}

	handle_if_init(*phandle);
	if ((*phandle)->num_ifaces == 0) {
		hal_printf(MSG_ERROR, "Failed to find any interfaces");
		free(*phandle);
		return WIFI_ERROR_UNINITIALIZED;
	}

	for (i = 0; i < (*phandle)->num_ifaces; i++) {
		u32 ifidx = (*phandle)->ifaces[i]->index;

		if (strncmp((*phandle)->ifaces[i]->name, "wlan", 4) != 0)
			continue;

		(*phandle)->drv = driver_if_init(*phandle, wifi_drv_event_cb,
						 ifidx);
		if ((*phandle)->drv)
			break;
	}

	if (!(*phandle)->drv) {
		hal_printf(MSG_ERROR,
			   "Failed initialize driver if");
		handle_if_deinit(*phandle);
		hal_debug_close_syslog();
		return WIFI_ERROR_UNINITIALIZED;
	}

	(*phandle)->magic = WIFI_INFO_MAGIC;

	for (i = 0; i < (*phandle)->num_ifaces; i++) {
		if (driver_get_interface_info((*phandle)->drv,
					      (*phandle)->ifaces[i]->index,
					      (*phandle)->ifaces[i]->mac_addr,
					      &(*phandle)->ifaces[i]->mode)) {
			hal_printf(MSG_ERROR, "Failed to get interface info");
			return WIFI_ERROR_UNINITIALIZED;
		}
	}

	hal_printf(MSG_DEBUG, "wifi HAL successfully initialized");
	return WIFI_SUCCESS;
}

void wifi_cleanup(wifi_handle handle, wifi_cleaned_up_handler handler)
{
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(handle, __func__))
		return;

	driver_if_deinit(handle->drv);
	handle->drv = NULL;
	handle_if_deinit(handle);

	if (handler)
		handler(handle);

	handle->magic = 0xFFFFFFFF;
	free(handle);
	hal_debug_close_syslog();
}

void wifi_event_loop(wifi_handle handle)
{
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(handle, __func__))
		return;

	driver_if_events(handle->drv);
}

void wifi_get_error_info(wifi_error err, const char **msg) {
	*msg = NULL;
}

wifi_error wifi_get_supported_feature_set(wifi_interface_handle handle,
					  feature_set *set)
{
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(handle, __func__))
		return WIFI_ERROR_INVALID_ARGS;

	if (!set) {
		hal_printf(MSG_ERROR, "%s: Invalid parameters.", __func__);
		return WIFI_ERROR_INVALID_ARGS;
	}

	*set = driver_if_get_feature_set(handle->handle->drv);
	return WIFI_SUCCESS;
}

wifi_error wifi_get_concurrency_matrix(wifi_interface_handle handle, int max_size,
				       feature_set *matrix, int *size)
{
	feature_set set;

#define SIZE_INC_AND_TEST()           \
do {                                  \
	(*size)++;                    \
	if (*size == max_size)        \
		return WIFI_SUCCESS;  \
} while (0)

	if (WIFI_INFO_INVALID(handle, __func__))
		return WIFI_ERROR_INVALID_ARGS;

	if (max_size <= 0 || !matrix || !size) {
		hal_printf(MSG_ERROR, "%s: Invalid parameters.", __func__);
		return WIFI_ERROR_INVALID_ARGS;
	}

	memset(matrix, 0, sizeof(feature_set) * max_size);
	*size = 0;
	set = driver_if_get_feature_set(handle->handle->drv);

	/*
	 * Station Concurrency with P2P and TDLS and another station.
	 * TODO: Currently Intel devices do not support P2P and TDLS
	 * concurrency, i.e., in case of P2P when there is a TDLS pairing the
	 * TDLS pairing will be torn down.
	 */
	if (set & WIFI_FEATURE_INFRA) {
		feature_set common = (set & (WIFI_FEATURE_INFRA |
					     WIFI_FEATURE_INFRA_5G |
					     WIFI_FEATURE_PNO |
					     WIFI_FEATURE_HOTSPOT |
					     WIFI_FEATURE_D2AP_RTT |
					     WIFI_FEATURE_D2D_RTT |
					     WIFI_FEATURE_EPR |
					     WIFI_FEATURE_ADDITIONAL_STA));

		if (!(set & (WIFI_FEATURE_P2P | WIFI_FEATURE_TDLS))) {
			matrix[*size] = common;
			SIZE_INC_AND_TEST();
		} else {
			if (set & WIFI_FEATURE_P2P) {
				matrix[*size] = common | WIFI_FEATURE_P2P;
				SIZE_INC_AND_TEST();
			}

			if (set & WIFI_FEATURE_TDLS) {
				matrix[*size] = common |
					(set & (WIFI_FEATURE_TDLS |
						WIFI_FEATURE_TDLS_OFFCHANNEL));
				SIZE_INC_AND_TEST();
			}
		}
	}

	/*
	 * Soft AP concurrency support.
	 * TODO: Currently assume that no off channel activities are allowed
	 * when AP is running.
	 */
	if (set & WIFI_FEATURE_SOFT_AP) {
		matrix[*size] = set & (WIFI_FEATURE_SOFT_AP |
				       WIFI_FEATURE_AP_STA);
		SIZE_INC_AND_TEST();
	}

#undef SIZE_INC_AND_TEST

	return WIFI_SUCCESS;
}

/* List of all supported channels, including 5GHz channels */
wifi_error wifi_get_supported_channels(wifi_handle handle, int *size, wifi_channel *list) {
	return WIFI_ERROR_UNINITIALIZED;
}

/* Enhanced power reporting */
wifi_error wifi_is_epr_supported(wifi_handle handle) {
	return WIFI_ERROR_UNINITIALIZED;
}

/* multiple interface support */
wifi_error wifi_get_ifaces(wifi_handle handle, int *num_ifaces,
			   wifi_interface_handle **ifaces)
{
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(handle, __func__))
		return WIFI_ERROR_INVALID_ARGS;

	if (!num_ifaces || !ifaces) {
		hal_printf(MSG_ERROR, "%s: Invalid parameters.", __func__);
		return WIFI_ERROR_INVALID_ARGS;
	}

	*num_ifaces = handle->num_ifaces;
	*ifaces = handle->ifaces;
	return WIFI_SUCCESS;
}

wifi_error wifi_get_iface_name(wifi_interface_handle iface, char *name,
			       size_t size)
{
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(iface, __func__))
		return WIFI_ERROR_INVALID_ARGS;

	if (strlen(iface->name) >= size - 1) {
		hal_printf(MSG_ERROR,
			   "%s: (size=%d) <= (required=%d)", __func__,
			   size, strlen(iface->name) + 1);
		return WIFI_ERROR_INVALID_ARGS;
	}
	strncpy(name, iface->name, size);
	return WIFI_SUCCESS;
}

wifi_error wifi_set_iface_event_handler(wifi_request_id id,
		wifi_interface_handle iface, wifi_event_handler eh) {
	return WIFI_ERROR_UNINITIALIZED;
}

wifi_error wifi_reset_iface_event_handler(wifi_request_id id,
		wifi_interface_handle iface) {
	return WIFI_ERROR_UNINITIALIZED;
}

wifi_error wifi_get_valid_channels(wifi_interface_handle handle,
				   int band, int max_channels,
				   wifi_channel *channels, int *num_channels)
{
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(handle, __func__))
		return WIFI_ERROR_INVALID_ARGS;

	if (max_channels <= 0 || !channels || !num_channels) {
		hal_printf(MSG_ERROR, "Invalid parameters for %s", __func__);
		return WIFI_ERROR_INVALID_ARGS;
	}

	*num_channels = max_channels;
	if (driver_get_channels(handle->handle->drv, (wifi_band)band,
				num_channels, channels) < 0)
		return WIFI_ERROR_UNKNOWN;

	return WIFI_SUCCESS;
}

wifi_error wifi_set_nodfs_flag(wifi_interface_handle iface, u32 nodfs) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_rtt_capabilities(wifi_interface_handle iface,
		wifi_rtt_capabilities *capabilities) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_start_logging(wifi_interface_handle iface, u32 verbose_level, u32 flags,
		u32 max_interval_sec, u32 min_data_size, char *buffer_name) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_set_country_code(wifi_interface_handle iface, const char *code) {
	char current_code[3];
	hal_printf(MSG_DEBUG, "%s", __func__);

	if (WIFI_INFO_INVALID(iface, __func__) || !code)
		return WIFI_ERROR_INVALID_ARGS;

	if (driver_get_country_code(iface->handle->drv, current_code) < 0)
		hal_printf(MSG_DEBUG,
			   "Current country information unavailable, setting country anyway");

	current_code[2] = '\0';
	if (!memcmp(code, current_code, 2)) {
		hal_printf(MSG_DEBUG, "Country code already set to %s - Skip",
			   current_code);
		return WIFI_SUCCESS;
	}

	if (driver_set_country_code(iface->handle->drv, code) < 0)
		return WIFI_ERROR_UNKNOWN;

	return WIFI_SUCCESS;
}

wifi_error wifi_get_firmware_memory_dump( wifi_interface_handle iface,
		wifi_firmware_memory_dump_handler handler) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_set_log_handler(wifi_request_id id, wifi_interface_handle iface,
		wifi_ring_buffer_data_handler handler) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_reset_log_handler(wifi_request_id id, wifi_interface_handle iface) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_set_alert_handler(wifi_request_id id, wifi_interface_handle iface,
		wifi_alert_handler handler) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_reset_alert_handler(wifi_request_id id, wifi_interface_handle iface) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_firmware_version( wifi_interface_handle iface, char *buffer,
        int buffer_size) {

	hal_printf(MSG_DEBUG, "%s", __func__);
	if ((WIFI_INFO_INVALID(iface, __func__)) || !(buffer && (buffer_size > 0)))
		return WIFI_ERROR_INVALID_ARGS;

	if (driver_get_fw_version(iface->handle->drv, buffer, buffer_size) < 0)
		return WIFI_ERROR_UNKNOWN;

	return WIFI_SUCCESS;
}

wifi_error wifi_get_ring_buffers_status(wifi_interface_handle iface,
		u32 *num_rings, wifi_ring_buffer_status *status) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_logger_supported_feature_set(wifi_interface_handle iface,
		unsigned int *support) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_ring_data(wifi_interface_handle iface, char *ring_name) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_driver_version(wifi_interface_handle iface, char *buffer,
        int buffer_size) {

	hal_printf(MSG_DEBUG, "%s", __func__);
	if ((WIFI_INFO_INVALID(iface, __func__)) || !(buffer && (buffer_size > 0)))
		return WIFI_ERROR_INVALID_ARGS;

	if (driver_get_drv_version(iface->handle->drv, buffer, buffer_size) < 0)
		return WIFI_ERROR_UNKNOWN;

	return WIFI_SUCCESS;
}

wifi_error wifi_enable_tdls(wifi_interface_handle iface, mac_addr addr,
		wifi_tdls_params *params, wifi_tdls_handler handler) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_disable_tdls(wifi_interface_handle iface, mac_addr addr) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_tdls_status(wifi_interface_handle iface, mac_addr addr,
		wifi_tdls_status *status) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_get_tdls_capabilities(wifi_interface_handle iface,
		wifi_tdls_capabilities *capabilities) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_set_bssid_hotlist(wifi_request_id id, wifi_interface_handle iface,
		wifi_bssid_hotlist_params params, wifi_hotlist_ap_found_handler handler) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_start_sending_offloaded_packet(wifi_request_id id,
		wifi_interface_handle iface, u8 *ip_packet, u16 ip_packet_len,
		u8 *src_mac_addr, u8 *dst_mac_addr, u32 period_msec) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_stop_sending_offloaded_packet(wifi_request_id id, wifi_interface_handle iface) {
	return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_set_scanning_mac_oui(wifi_interface_handle iface, unsigned char *buffer) {
	/*
	 * This function is obsolete.
	 * As agreed with Google, returning success.
	 */
	return WIFI_SUCCESS;
}

wifi_error wifi_virtual_interface_create(wifi_handle handle, const char* ifname,
        wifi_interface_type iface_type)
{
	/*
	 * wlan0(sta) and wlan1(ap) interface will be created in init.rc by iw add command
	 */
	hal_printf(MSG_DEBUG, "%s", __func__);
	return WIFI_SUCCESS;
}

wifi_error init_wifi_vendor_hal_func_table(wifi_hal_fn *hal_fn) {
	if (hal_fn == NULL) {
		return WIFI_ERROR_UNINITIALIZED;
	}

	hal_fn->wifi_initialize = wifi_initialize;
	hal_fn->wifi_cleanup = wifi_cleanup;
	hal_fn->wifi_event_loop = wifi_event_loop;
	hal_fn->wifi_get_error_info = wifi_get_error_info;
	hal_fn->wifi_get_supported_feature_set = wifi_get_supported_feature_set;
	hal_fn->wifi_get_concurrency_matrix = wifi_get_concurrency_matrix;
	hal_fn->wifi_get_supported_channels = wifi_get_supported_channels;
	hal_fn->wifi_get_ifaces = wifi_get_ifaces;
	hal_fn->wifi_get_iface_name = wifi_get_iface_name;
	hal_fn->wifi_get_valid_channels = wifi_get_valid_channels;
	hal_fn->wifi_start_logging = wifi_start_logging;
	hal_fn->wifi_set_country_code = wifi_set_country_code;
	hal_fn->wifi_enable_tdls = wifi_enable_tdls;
	hal_fn->wifi_disable_tdls = wifi_disable_tdls;
	hal_fn->wifi_get_tdls_status = wifi_get_tdls_status;
	hal_fn->wifi_get_tdls_capabilities = wifi_get_tdls_capabilities;
	hal_fn->wifi_set_nodfs_flag = wifi_set_nodfs_flag;
	hal_fn->wifi_get_firmware_memory_dump = wifi_get_firmware_memory_dump;
	hal_fn->wifi_set_log_handler = wifi_set_log_handler;
	hal_fn->wifi_reset_log_handler = wifi_reset_log_handler;
	hal_fn->wifi_set_alert_handler = wifi_set_alert_handler;
	hal_fn->wifi_reset_alert_handler = wifi_reset_alert_handler;
	hal_fn->wifi_get_firmware_version = wifi_get_firmware_version;
	hal_fn->wifi_get_ring_buffers_status = wifi_get_ring_buffers_status;
	hal_fn->wifi_get_logger_supported_feature_set = wifi_get_logger_supported_feature_set;
	hal_fn->wifi_get_ring_data = wifi_get_ring_data;
	hal_fn->wifi_get_driver_version = wifi_get_driver_version;
	hal_fn->wifi_start_sending_offloaded_packet = wifi_start_sending_offloaded_packet;
	hal_fn->wifi_stop_sending_offloaded_packet = wifi_stop_sending_offloaded_packet;
	hal_fn->wifi_is_epr_supported = wifi_is_epr_supported;
	hal_fn->wifi_reset_iface_event_handler = wifi_reset_iface_event_handler;
	hal_fn->wifi_set_scanning_mac_oui = wifi_set_scanning_mac_oui;
	hal_fn->wifi_virtual_interface_create = wifi_virtual_interface_create;
	return WIFI_SUCCESS;
}
