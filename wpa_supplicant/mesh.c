/*
 * WPA Supplicant - Basic mesh mode routines
 * Copyright (c) 2013, Thomas Pedersen <thomas@cozybit.com>
 * Copyright (c) 2013, cozybit, Inc.
 *
 * XXX: license?
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
	wpa_msg(wpa_s, MSG_INFO, "JOINING MESH!");
	return 0;
}
