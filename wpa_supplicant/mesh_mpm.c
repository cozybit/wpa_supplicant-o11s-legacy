/*
 * Copyright (c) 2013, cozybit, Inc.
 *
 * All right reserved.
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
#include "ap/sta_info.h"
#include "ap/hostapd.h"

/* XXX: lifted from src/ap/ieee802_11.c */
static u16 copy_supp_rates(struct wpa_supplicant *wpa_s,
			   struct sta_info *sta,
			   struct ieee802_11_elems *elems)
{
	if (!elems->supp_rates) {
		wpa_msg(wpa_s, MSG_ERROR, "no supported rates from " MACSTR,
			MAC2STR(sta->addr));
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (elems->supp_rates_len + elems->ext_supp_rates_len >
	    sizeof(sta->supported_rates)) {
		wpa_msg(wpa_s, MSG_ERROR, "Invalid supported rates element length " MACSTR
			" %d+%d ", MAC2STR(sta->addr), elems->supp_rates_len,
			elems->ext_supp_rates_len);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->supported_rates_len = merge_byte_arrays(
		sta->supported_rates, sizeof(sta->supported_rates),
		elems->supp_rates, elems->supp_rates_len,
		elems->ext_supp_rates, elems->ext_supp_rates_len);

	return WLAN_STATUS_SUCCESS;
}

/* TODO: teardown functions for these */
static struct sta_info *
mesh_get_sta(struct hostapd_data *data, const u8 *sta)
{
	struct sta_info *s;

	s = data->sta_hash[STA_HASH(sta)];
	while (s != NULL && os_memcmp(s->addr, sta, 6) != 0)
		s = s->hnext;
	return s;
}

static void
mesh_sta_hash_add(struct hostapd_data *data, struct sta_info *sta)
{
	sta->hnext = data->sta_hash[STA_HASH(sta->addr)];
	data->sta_hash[STA_HASH(sta->addr)] = sta;
}

static struct sta_info *
mesh_sta_add(struct hostapd_data *data, const u8 *addr)
{
	struct sta_info *sta;

	sta = mesh_get_sta(data, addr);
	if (sta)
		return sta;

	wpa_printf(MSG_DEBUG, "  New STA");
	if (data->num_sta >= data->max_num_sta) {
		/* FIX: might try to remove some old STAs first? */
		wpa_printf(MSG_DEBUG, "no more room for new STAs (%d/%d)",
			   data->num_sta, data->max_num_sta);
		return NULL;
	}

	sta = os_zalloc(sizeof(struct sta_info));
	if (sta == NULL) {
		wpa_printf(MSG_ERROR, "malloc failed");
		return NULL;
	}

	/* initialize STA info data */
	os_memcpy(sta->addr, addr, ETH_ALEN);
	sta->next = data->sta_list;
	data->sta_list = sta;
	data->num_sta++;
	mesh_sta_hash_add(data, sta);
	/* XXX: hmm */
	//sta->ssid = &hapd->conf->ssid;

	return sta;
}

/* configure peering state in ours and driver's station entry */
static void
wpa_mesh_set_plink_state(struct wpa_supplicant *wpa_s, struct sta_info *sta,
			 enum mesh_plink_state state)
{
	struct hostapd_sta_add_params params;
	int ret;

	sta->plink_state = state;

	os_memset(&params, 0, sizeof(params));
	params.addr = sta->addr;
	params.plink_state = state;
	params.set = 1;

	if ((ret = wpa_drv_sta_add(wpa_s, &params)))
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to set " MACSTR ": %d",
			MAC2STR(sta->addr), ret);
	return;
}

void
wpa_mesh_new_mesh_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
		       struct ieee802_11_elems *elems)
{
	struct hostapd_sta_add_params params;
	/* struct wmm_information_element *wmm; */
	struct hostapd_data *data = wpa_s->ifmsh->bss[0];
	struct sta_info *sta = mesh_sta_add(data, addr);

	int ret = 0;
	if (!sta)
		return;

	/* initialize sta */
	if (copy_supp_rates(wpa_s, sta, elems))
		return;

	/* TODO: our beacons currently don't include this */
	/*
	if (!elems->wmm) {
		wpa_msg(wpa_s, MSG_ERROR, "all mesh STAs should have a QoS IE!");
		return;
	}
	wmm = (struct wmm_information_element *) elems->wmm;
	sta->qosinfo = wmm->qos_info;
	*/

	sta->plink_state = PLINK_LISTEN;

	/* insert into driver */
	os_memset(&params, 0, sizeof(params));
	params.supp_rates = sta->supported_rates;
	params.supp_rates_len = sta->supported_rates_len;
	params.addr = addr;
	params.plink_state = sta->plink_state;
	/* llid actually */
	params.aid = 1;
	/* not used for mesh */
	params.listen_interval = 100;
	/* TODO: HT capabilities */
	/* TODO: flags? drv_flags? */
	params.flags |= WPA_STA_WMM;
	/* XXX: hardcode open mesh for now, and nl80211 authenticates station
	 * by default */
	params.flags |= WPA_STA_AUTHORIZED;
	//params.qosinfo = sta->qosinfo;
	if ((ret = wpa_drv_sta_add(wpa_s, &params)))
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to insert " MACSTR ": %d",
			MAC2STR(addr), ret);

	/* XXX: no peering frame tx/rx yet, so just force ESTAB for now */
	wpa_mesh_set_plink_state(wpa_s, sta, PLINK_ESTAB);
	return;
}

static void mesh_mpm_send_plink_action(struct wpa_supplicant *wpa_s,
				       struct sta_info *sta,
				       enum plink_action_field type,
				       unsigned short close_reason)
{
	struct wpabuf *buf;
	int ret;

	/* TODO figure out max size of elems here */
	buf = wpabuf_alloc(1500);
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_SELF_PROTECTED);
	wpabuf_put_u8(buf, type);

	/* TODO add capability info & aid */
	/* TODO IE: All the static IEs */
	/* TODO IE: mesh config */
        /* TODO (mesh config) IIRC all the defaults are 0. Double check */
        /* TODO IE: Mesh Peering Management element */
        /* TODO HT IEs */
        /* TODO IE: Add MIC and encrypted AMPE */
        /* TODO protect_frame() */

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0,
				sta->addr, wpa_s->own_addr, wpa_s->own_addr,
				wpabuf_head(buf), wpabuf_len(buf), 0);
	if (ret < 0)
		wpa_msg(wpa_s, MSG_INFO, "Mesh MPM: failed to send peering frame");

	wpabuf_free(buf);
}

void mesh_mpm_mgmt_rx(struct wpa_supplicant *wpa_s,
		      struct rx_mgmt *rx_mgmt)
{
	/* TODO handle auth frames and such. */
}

void mesh_mpm_action_rx(struct wpa_supplicant *wpa_s,
			struct rx_action *rx_action)
{
	unsigned char action_field;
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct sta_info *sta;

	if (rx_action->category != WLAN_ACTION_SELF_PROTECTED)
		return;

	/* action code, mesh id and peering mgmt */
	if (rx_action->len < 1 + 2 + 2)
		return;

	action_field = rx_action->data[0];

	/* TODO check that mesh peering, meshid, meshconfig IEs are there.. */
	/* TODO parse IEs */
	/* TODO extract plid/llid from peering IE */
	/* TODO check rateset */

	sta = mesh_get_sta(hapd, rx_action->sa);
	if (!sta)
		return;
	/* TODO check peer is sae_accepted */
	/* TODO init ampe state for sta */
	/* TODO copy sup rates */
	/* TODO check frame protection */

	if (sta->plink_state == PLINK_BLOCKED)
		return;

	/* TODO state machine */
}

