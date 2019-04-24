/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 * Copyright(c) 2019 Intel Corporation
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
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
 * Copyright(c) 2016 Intel Deutschland GmbH
 * Copyright(c) 2019 Intel Corporation
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
#ifndef __VENDOR_CMD_H__
#define __VENDOR_CMD_H__

#define INTEL_OUI	0x001735

/**
 * enum iwl_mvm_vendor_cmd - supported vendor commands
 * @IWL_MVM_VENDOR_CMD_RXFILTER: Set/clear rx filter.
 * @IWL_MVM_VENDOR_CMD_GET_FW_VERSION: query the current f/w version
 * @IWL_MVM_VENDOR_CMD_GET_DRV_VERSION: query the current driver version
 */

enum iwl_mvm_vendor_cmd {
	IWL_MVM_VENDOR_CMD_RXFILTER,
	IWL_MVM_VENDOR_CMD_GET_FW_VERSION,
	IWL_MVM_VENDOR_CMD_GET_DRV_VERSION,
};

/**
 * enum iwl_mvm_vendor_rxfilter_flags - the type of request rxfilter
 *
 * @IWL_MVM_VENDOR_RXFILTER_UNICAST: control unicast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_BCAST: control broadcast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_MCAST4: control IPv4 multicast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_MCAST6: control IPv4 multicast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_EINVAL: no Rx filter command was set
 *
 */
enum iwl_mvm_vendor_rxfilter_flags {
	IWL_MVM_VENDOR_RXFILTER_UNICAST = 1 << 0,
	IWL_MVM_VENDOR_RXFILTER_BCAST = 1 << 1,
	IWL_MVM_VENDOR_RXFILTER_MCAST4 = 1 << 2,
	IWL_MVM_VENDOR_RXFILTER_MCAST6 = 1 << 3,
	IWL_MVM_VENDOR_RXFILTER_EINVAL = 1 << 7,
};

/**
 * enum iwl_mvm_vendor_rxfilter_op - the operation associated with a filter
 *
 * @IWL_MVM_VENDOR_RXFILTER_OP_PASS: pass frames matching the filter
 * @IWL_MVM_VENDOR_RXFILTER_OP_DROP: drop frames matching the filter
 */
enum iwl_mvm_vendor_rxfilter_op {
	IWL_MVM_VENDOR_RXFILTER_OP_PASS,
	IWL_MVM_VENDOR_RXFILTER_OP_DROP,
};

/**
 * enum iwl_mvm_vendor_attr - attributes used in vendor commands
 * @__IWL_MVM_VENDOR_ATTR_INVALID: attribute 0 is invalid
 * @IWL_MVM_VENDOR_ATTR_RXFILTER: u32 attribute.
 *      See %iwl_mvm_vendor_rxfilter_flags.
 * @IWL_MVM_VENDOR_ATTR_RXFILTER_OP: u32 attribute.
 *      See %iwl_mvm_vendor_rxfilter_op.
 * @NUM_IWL_MVM_VENDOR_ATTR: number of vendor attributes
 * @MAX_IWL_MVM_VENDOR_ATTR: highest vendor attribute number
 * @IWL_MVM_VENDOR_ATTR_DRV_VER: string attribute
 * @IWL_MVM_VENDOR_ATTR_FW_VER: string attribute
 */
enum iwl_mvm_vendor_attr {
	__IWL_MVM_VENDOR_ATTR_INVALID,
	IWL_MVM_VENDOR_ATTR_RXFILTER,
	IWL_MVM_VENDOR_ATTR_RXFILTER_OP,
	IWL_MVM_VENDOR_ATTR_DRV_VER,
        IWL_MVM_VENDOR_ATTR_FW_VER,

	NUM_IWL_MVM_VENDOR_ATTR,
	MAX_IWL_MVM_VENDOR_ATTR = NUM_IWL_MVM_VENDOR_ATTR - 1,
};
#endif /* __VENDOR_CMD_H__ */
