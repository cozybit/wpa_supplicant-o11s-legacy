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

#include "ap/hostapd.h"
#include "ap/ieee802_11.h"


static void
wpa_supplicant_mesh_deinit(struct wpa_supplicant *wpa_s)
{
	wpa_supplicant_mesh_iface_deinit(wpa_s->ifmsh);
	wpa_s->ifmsh = NULL;
	/* TODO: leave mesh (stop beacon). This will happen on link down
	 * anyway, so it's not urgent */
	return;
}

void wpa_supplicant_mesh_iface_deinit(struct hostapd_iface *ifmsh)
{
	int i;
	if (!ifmsh)
		return;

	if (ifmsh->mconf) {
		os_free(ifmsh->mconf);
		if (ifmsh->mconf->ies)
			os_free(ifmsh->mconf->ies);
	}

	mesh_mpm_deinit(ifmsh);
	/* take care of shared data */
	hostapd_interface_free(ifmsh);
	return;
}

static struct mesh_conf *
mesh_config_create(struct wpa_ssid *ssid)
{
	struct mesh_conf *conf;

	conf = os_zalloc(sizeof(struct mesh_conf));
	if (!conf)
		return NULL;

	os_memcpy(conf->meshid, ssid->ssid, ssid->ssid_len);
	conf->meshid_len = ssid->ssid_len;

	if (ssid->auth_alg & WPA_AUTH_ALG_SAE)
		conf->security |= MESH_CONF_SEC_AUTH;
	else
		conf->security |= MESH_CONF_SEC_NONE;

	/* defaults */
	conf->mesh_pp_id = MESH_PATH_PROTOCOL_HWMP;
	conf->mesh_pm_id = MESH_PATH_METRIC_AIRTIME;
	conf->mesh_cc_id = 0;
	conf->mesh_sp_id = MESH_SYNC_METHOD_NEIGHBOR_OFFSET;
	/* TODO: should be 1 for SAE, but the kernel fails to set this in its
	 * beacon, so neither peer will get CMD_NEW_PEER_CANDIDATE since
	 * mesh_matches_local() fails. Easy patch in
	 * net/mac80211/mesh.c:ieee80211_start_mesh()*/
	conf->mesh_auth_id = 0;

	/* TODO: fill this in */
	if (conf->security & MESH_CONF_SEC_AUTH) {
		conf->ies = os_zalloc(2);
		if (!conf->ies)
			goto out_free;

		conf->ies[0] = WLAN_EID_RSN;
		conf->ies[1] = 0;
		conf->ie_len = 2;
	}

	return conf;
out_free:
	os_free (conf->ies);
	os_free (conf);
	return NULL;
}

static int
wpa_supplicant_mesh_init(struct wpa_supplicant *wpa_s,
			 struct wpa_ssid *ssid)
{
	struct hostapd_iface *ifmsh;
	struct hostapd_data *bss;
	struct hostapd_config *conf;
	struct mesh_conf *mconf;
	int basic_rates_erp[] = {10, 20, 55, 60, 110, 120, 240, -1 };

	if (!wpa_s->conf->user_mpm)
		/* not much for us to do here */
		return 0;

	/* TODO: register CMD_NEW_PEER_CANDIDATE events, setup RSN IEs if RSN
	 * mesh, and init MPM in general */
	wpa_s->ifmsh = ifmsh = os_zalloc(sizeof(*wpa_s->ifmsh));
	if (!ifmsh)
		return -ENOMEM;

	ifmsh->num_bss = 1;
	ifmsh->bss = os_calloc(wpa_s->ifmsh->num_bss,
			       sizeof(struct hostapd_data *));
	if (!ifmsh->bss)
		goto out_free;

	/* FIXME - various uninitialized ptrs here. */
	ifmsh->bss[0] = bss = os_zalloc(sizeof(struct hostapd_data));
	if (!bss)
		goto out_free;

	os_memcpy(bss->own_addr, wpa_s->own_addr, ETH_ALEN);
	bss->driver = wpa_s->driver;
	bss->drv_priv = wpa_s->drv_priv;
	bss->iface = ifmsh;
	wpa_s->assoc_freq = ssid->frequency;
	wpa_s->current_ssid = ssid;

	/* setup an AP config for auth processing */
	conf = hostapd_config_defaults();
	if (!conf)
		goto out_free;

	bss->conf = conf->bss;
	bss->iconf = conf;
	ifmsh->conf = conf;
	ifmsh->bss[0]->max_num_sta = 10;

	mconf = mesh_config_create(ssid);
	if (!mconf)
		goto out_free;
	ifmsh->mconf = mconf;

	/* need conf->hw_mode for supported rates. */
	/* c.f. wpa_supplicant/ap.c:wpa_supplicant_conf_ap() */
	if (ssid->frequency == 0) {
		/* default channel 11 */
		/* XXX: this doesn't make it to join_mesh() */
		conf->hw_mode = HOSTAPD_MODE_IEEE80211G;
		conf->channel = 11;
	} else if (ssid->frequency >= 2412 && ssid->frequency <= 2472) {
		conf->hw_mode = HOSTAPD_MODE_IEEE80211G;
		conf->channel = (ssid->frequency - 2407) / 5;
	} else if ((ssid->frequency >= 5180 && ssid->frequency <= 5240) ||
		   (ssid->frequency >= 5745 && ssid->frequency <= 5825)) {
		conf->hw_mode = HOSTAPD_MODE_IEEE80211A;
		conf->channel = (ssid->frequency - 5000) / 5;
	} else if (ssid->frequency >= 56160 + 2160 * 1 &&
		   ssid->frequency <= 56160 + 2160 * 4) {
		conf->hw_mode = HOSTAPD_MODE_IEEE80211AD;
		conf->channel = (ssid->frequency - 56160) / 2160;
	} else {
		wpa_printf(MSG_ERROR, "Unsupported mesh mode frequency: %d MHz",
			   ssid->frequency);
		goto out_free;
	}

	/* XXX: hack! this is so an MPM which correctly sets the ERP
	 * mandatory rates as BSSBasicRateSet doesn't reject us. We
	 * could add a new hw_mode HOSTAPD_MODE_IEEE80211G_ERP, but
	 * this is way easier. This also makes our BSSBasicRateSet
	 * advertised in beacons match the one in peering frames, sigh.
	 * */
	if (conf->hw_mode == HOSTAPD_MODE_IEEE80211G) {
		conf->basic_rates = os_zalloc(sizeof(basic_rates_erp));
		if (!conf->basic_rates)
			goto out_free;
		os_memcpy(conf->basic_rates,
			  basic_rates_erp, sizeof(basic_rates_erp));
	}

	/* XXX: we could use hostapd_setup_interface(), except the mesh
	 * interface returns -EBUSY when attempting to set the frequency, so
	 * instead duplicate the parts we want here. */
	if (hostapd_get_hw_features(ifmsh))
		goto out_free;
	if (hostapd_select_hw_mode(ifmsh))
		goto out_free;
	if (hostapd_prepare_rates(ifmsh, ifmsh->current_mode))
		goto out_free;

	return 0;
out_free:
	wpa_supplicant_mesh_deinit(wpa_s);
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

	if (wpa_s->conf->user_mpm) {
		params.flags |= WPA_DRIVER_MESH_FLAG_USER_MPM;
		params.conf.flags &= ~WPA_DRIVER_MESH_CONF_FLAG_AUTO_PLINKS;
	} else {
		params.flags |= WPA_DRIVER_MESH_FLAG_DRIVER_MPM;
		params.conf.flags |= WPA_DRIVER_MESH_CONF_FLAG_AUTO_PLINKS;
	}

	if (ssid->auth_alg & WPA_AUTH_ALG_SAE)
		params.flags |= WPA_DRIVER_MESH_FLAG_SAE_AUTH;

	if (wpa_supplicant_mesh_init(wpa_s, ssid)) {
		wpa_msg(wpa_s, MSG_ERROR, "failed to init mesh");
		goto out;
	}

	if (wpa_s->ifmsh) {
		params.ies = wpa_s->ifmsh->mconf->ies;
		params.ie_len = wpa_s->ifmsh->mconf->ie_len;
	}

	wpa_msg(wpa_s, MSG_INFO, "joining mesh %s",
		wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
	ret = wpa_drv_join_mesh(wpa_s, &params);
	if (ret)
		wpa_msg(wpa_s, MSG_ERROR, "mesh join error=%d\n", ret);
	/* hostapd sets the interface down until we associate */
	wpa_drv_set_operstate(wpa_s, 1);
out:
	return ret;
}
