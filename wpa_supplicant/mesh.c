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
#include "mesh_mpm.h"
#include "notify.h"

static void
wpa_supplicant_mesh_deinit(struct wpa_supplicant *wpa_s)
{
	wpa_supplicant_mesh_iface_deinit(wpa_s->ifmsh);
	wpa_s->ifmsh = NULL;
	return;
}

void wpa_supplicant_mesh_iface_deinit(struct mesh_iface *ifmsh)
{
	if (!ifmsh)
		return;

	os_free(ifmsh->ies);
	os_free(ifmsh->bss);
	os_free(ifmsh);
	return;
}

static int
wpa_supplicant_mesh_init(struct wpa_supplicant *wpa_s,
			 struct wpa_ssid *ssid)
{
	if (!wpa_s->conf->user_mpm)
		/* not much for us to do here */
		return 0;

	/* TODO: register CMD_NEW_PEER_CANDIDATE events, setup RSN IEs if RSN
	 * mesh, and init MPM in general */
	wpa_s->ifmsh = os_zalloc(sizeof(*wpa_s->ifmsh));
	if (!wpa_s->ifmsh)
		return -ENOMEM;

	/* need dummy RSN IEs so peer kernel doesn't ignore our beacons... */
	wpa_s->ifmsh->ies = os_zalloc(2);
	if (!wpa_s->ifmsh->ies)
		goto out_free;

	wpa_s->ifmsh->ies[0] = WLAN_EID_RSN;
	wpa_s->ifmsh->ies[1] = 0;
	wpa_s->ifmsh->ie_len = 2;

	wpa_s->ifmsh->bss = os_zalloc(sizeof *wpa_s->ifmsh->bss);
	if (!wpa_s->ifmsh->bss)
		goto out_free;
	wpa_s->ifmsh->bss->max_num_sta = 10;


	return 0;
out_free:
	if (wpa_s->ifmsh) {
		os_free(wpa_s->ifmsh->ies);
		os_free(wpa_s->ifmsh->bss);
		os_free(wpa_s->ifmsh);
	}
	return -ENOMEM;
}

void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, int ie_len)
{
	struct ieee802_11_elems elems;

	wpa_msg(wpa_s, MSG_INFO,
		"new peer notification for " MACSTR, MAC2STR(addr));

        if (ieee802_11_parse_elems(ies, ie_len, &elems, 0) == ParseFailed) {
                wpa_msg(wpa_s, MSG_INFO, "Could not parse beacon from " MACSTR,
                           MAC2STR(addr));
                return;
        }

	/* TODO: verify this peer matches MBSS before inserting! */
	/* TODO: process in SAE, which will allocate station if authenticated. */
	/* just immediately allocate peer for now, and insert into driver */
	wpa_mesh_new_mesh_peer(wpa_s, addr, &elems);
}

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid)
{
	struct wpa_driver_mesh_join_params params;
	int ret = 0;

	if (!ssid || !ssid->ssid || !ssid->ssid_len) {
		ret = -ENOENT;
		goto out;
	}

	wpa_supplicant_mesh_deinit(wpa_s);

	os_memset(&params, 0, sizeof(params));
	params.meshid = ssid->ssid;
	params.meshid_len = ssid->ssid_len;
	params.freq = ssid->frequency;
	params.flags = wpa_s->conf->user_mpm ?
		       WPA_DRIVER_MESH_FLAG_USER_MPM :
		       WPA_DRIVER_MESH_FLAG_DRIVER_MPM;

	if (wpa_supplicant_mesh_init(wpa_s, ssid)) {
		wpa_msg(wpa_s, MSG_ERROR, "failed to init mesh");
		goto out;
	}

	if (wpa_s->ifmsh) {
		params.ies = wpa_s->ifmsh->ies;
		params.ie_len = wpa_s->ifmsh->ie_len;
	}

	wpa_msg(wpa_s, MSG_INFO, "joining mesh %s",
		wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
	ret = wpa_drv_join_mesh(wpa_s, &params);
	if (ret)
		wpa_msg(wpa_s, MSG_ERROR, "mesh join error=%d\n", ret);
out:
	return ret;
}
