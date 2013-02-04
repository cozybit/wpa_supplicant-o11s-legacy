/*
 * WPA Supplicant - Basic mesh mode routines
 * Copyright (c) 2013, Thomas Pedersen <thomas@cozybit.com>
 * Copyright (c) 2013, cozybit, Inc.
 *
 * All rights reserved.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/uuid.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "common/ieee802_11_defs.h"
#include "config_ssid.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "mesh.h"
#include "notify.h"

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid)
{
	struct wpa_driver_mesh_join_params params;
	int ret = 0;

	if (!ssid || !ssid->ssid || !ssid->ssid_len) {
		ret = -ENOENT;
		goto out;
	}

	os_memset(&params, 0, sizeof(params));
	params.meshid = ssid->ssid;
	params.meshid_len = ssid->ssid_len;
	params.freq = ssid->frequency;
	wpa_msg(wpa_s, MSG_INFO, "joining mesh %s",
		wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
	ret = wpa_drv_join_mesh(wpa_s, &params);
	if (ret)
		wpa_msg(wpa_s, MSG_ERROR, "mesh join error=%d\n", ret);
out:
	return ret;
}
