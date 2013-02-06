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

	/* TODO: get qosinfo from WMM element. Apparently our mesh STAs don't
	 * include the WMM IE in their beacons, but setting the WLAN_STA_WMM
	 * bit below is also not enough for the kernel to mark this sta as WMM.
	 * Maybe a valid qosinfo would help?
	 */
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
	params.flags |= WLAN_STA_WMM;
	//params.qosinfo = sta->qosinfo;
	if ((ret = wpa_drv_sta_add(wpa_s, &params)))
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to insert " MACSTR ": %d",
			MAC2STR(addr), ret);
	return;
}
