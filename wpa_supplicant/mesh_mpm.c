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

struct mesh_peer_mgmt_ie {
	const u8 *proto_id;
	const u8 *llid;
	const u8 *plid;
	const u8 *reason;
	const u8 *pmk;
};

static int mesh_mpm_parse_peer_mgmt(struct wpa_supplicant *wpa_s,
				    u8 action_field,
				    const u8 *ie, size_t len,
				    struct mesh_peer_mgmt_ie *mpm_ie)
{
	os_memset(mpm_ie, 0, sizeof(*mpm_ie));

	/* remove optional pmk at end */
	if (len >= 16) {
		len -= 16;
		mpm_ie->pmk = ie + len - 16;
	}

	if ((action_field == PLINK_OPEN && len != 4) ||
	    (action_field == PLINK_CONFIRM && len != 6) ||
	    (action_field == PLINK_CLOSE && len != 6 && len != 8)) {
		wpa_msg(wpa_s, MSG_DEBUG, "MPM: invalid peer mgmt ie");
		return -1;
	}

	/* required fields */
	mpm_ie->proto_id = ie;
	mpm_ie->llid = ie + 2;
	ie += 4;
	len -= 4;

	/* close reason is always present at end for close */
	if (action_field == PLINK_CLOSE) {
		mpm_ie->reason = ie + len - 2;
		len -= 2;
	}
	/* plid, present for confirm, and possibly close */
	if (len)
		mpm_ie->plid = ie;

	return 0;
}

enum plink_event {
        PLINK_UNDEFINED,
        OPN_ACPT,
        OPN_RJCT,
        OPN_IGNR,
        CNF_ACPT,
        CNF_RJCT,
        CNF_IGNR,
        CLS_ACPT,
        CLS_IGNR
};

static int plink_free_count()
{
	/* TODO */
	return 99;
}

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
	struct mesh_iface *ifmsh = wpa_s->ifmsh;
	struct mesh_conf *conf = ifmsh->conf;
	u8 ie_len, add_plid = 0;
	int ret;

	buf = wpabuf_alloc(2 +      /* capability info */
			   2 +      /* AID */
			   2 + 8 +  /* supported rates */
			   2 + (32 - 8) +
			   2 + 32 + /* mesh ID */
			   2 + 7 +  /* mesh config */
			   2 + 26 + /* HT capabilities */
			   2 + 22 + /* HT operation */
			   2 + 23);   /* peering management */
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_SELF_PROTECTED);
	wpabuf_put_u8(buf, type);

	if (type != PLINK_CLOSE) {
		/* TODO: security bit */
		wpabuf_put_le16(buf, 0);
		if (type == PLINK_CONFIRM)
			/* TODO: AID? */
			wpabuf_put_le16(buf, 0);
	}
	/* TODO IE: All the static IEs */
	/* hostap_eid_supp_rates */

	/* IE: Mesh ID */
	wpabuf_put_u8(buf, WLAN_EID_MESH_ID);
	wpabuf_put_u8(buf, conf->meshid_len);
	wpabuf_put_data(buf, conf->meshid, conf->meshid_len);

	/* XXX: kernel MPM will drop our peering frame if mesh conf or
	 * supported rates (basic rate set) doesn't match! */
	/* IE: mesh conf */
	wpabuf_put_u8(buf, WLAN_EID_MESH_CONFIG);
	wpabuf_put_u8(buf, 8);
	wpabuf_put_u8(buf, conf->mesh_pp_id);
	wpabuf_put_u8(buf, conf->mesh_pm_id);
	wpabuf_put_u8(buf, conf->mesh_cc_id);
	wpabuf_put_u8(buf, conf->mesh_sp_id);
	wpabuf_put_u8(buf, conf->mesh_auth_id);
	/* TODO: formation info */
	wpabuf_put_u8(buf, 0);
	/* always forwarding & accepting plinks for now */
	/* TODO: PS bits */
	wpabuf_put_u8(buf, 0x1 | 0x8);
	wpabuf_put_u8(buf, 0);

        /* IE: Mesh Peering Management element */
	ie_len = 4;
	switch (type) {
	case PLINK_OPEN:
		break;
	case PLINK_CONFIRM:
		ie_len += 2;
		add_plid = 1;
		break;
	case PLINK_CLOSE:
		if (sta) {
			ie_len += 2;
			add_plid = 1;
		}
		ie_len += 2; /* reason code */
		break;
	}

	wpabuf_put_u8(buf, WLAN_EID_PEER_MGMT);
	wpabuf_put_u8(buf, ie_len);
	/* default peering protocol */
	wpabuf_put_le16(buf, 0);
	if (sta)
		wpabuf_put_le16(buf, sta->my_lid);
	else
		wpabuf_put_le16(buf, 0);
	if (add_plid)
		wpabuf_put_le16(buf, sta->peer_lid);
	if (type == PLINK_CLOSE)
		wpabuf_put_le16(buf, close_reason);
	else
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

static void mesh_mpm_fsm_restart(struct wpa_supplicant *wpa_s,
				 struct sta_info *sta)
{
	sta->plink_state = PLINK_LISTEN;
	/*
	sta->my_lid = sta->peer_lid = sta->reason = 0;
	sta->retries = 0;
	*/
}

static void mesh_mpm_fsm(struct wpa_supplicant *wpa_s, struct sta_info *sta,
			 enum plink_event next_state)
{
	unsigned short reason = 0;

	switch (sta->plink_state) {
	case PLINK_LISTEN:
		switch (next_state) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			break;
		case OPN_ACPT:
			/* TODO
			sta->timeout = aconf->retry_timeout_ms;
			sta->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, sta);
			*/
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;

	case PLINK_OPEN_SENT:
		switch (next_state) {
		case OPN_RJCT:
		case CNF_RJCT:
			/* TODO reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION); */
		case CLS_ACPT:
			sta->plink_state = PLINK_HOLDING;
			/* TODO
			if (!reason)
				reason = htole16(MESH_CLOSE_RCVD);
			sta->reason = reason;
			sta->timeout = aconf->holding_timeout_ms;
			sta->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			*/
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			/* retry timer is left untouched */
			sta->plink_state = PLINK_OPEN_RCVD;
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			sta->plink_state = PLINK_CNF_RCVD;
			/* TODO
			cand->timeout = aconf->confirm_timeout_ms;
			cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			*/
			break;
		default:
			break;
		}
		break;

	case PLINK_OPEN_RCVD:
		switch (next_state) {
		case OPN_RJCT:
		case CNF_RJCT:
			/* TODO reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION); */
		case CLS_ACPT:
			sta->plink_state = PLINK_HOLDING;
			/* TODO
			if (!reason)
				reason = htole16(MESH_CLOSE_RCVD);
			sta->reason = reason;
			sta->timeout = aconf->holding_timeout_ms;
			sta->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			*/
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			sta->plink_state = PLINK_ESTAB;
			/* TODO
			derive_mtk(cand);
			estab_peer_link(cand->peer_mac,
				cand->mtk, sizeof(cand->mtk),
				cand->mgtk, sizeof(cand->mgtk),
				cand->mgtk_expiration,
				cand->sup_rates,
				cand->sup_rates_len,
				cand->cookie);
			changed |= mesh_set_ht_op_mode(cand->conf->mesh);
			*/
			wpa_msg(wpa_s, MSG_INFO, "mesh plink with "
				MACSTR " established\n", MAC2STR(sta->addr));
			break;
		default:
			break;
		}
		break;

	case PLINK_CNF_RCVD:
		switch (next_state) {
		case OPN_RJCT:
		case CNF_RJCT:
			/* TODO reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION); */
		case CLS_ACPT:
			sta->plink_state = PLINK_HOLDING;
			/* TODO
			if (!reason)
				reason = htole16(MESH_CLOSE_RCVD);
			sta->reason = reason;
			cand->timeout = aconf->holding_timeout_ms;
			cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			*/
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			sta->plink_state = PLINK_ESTAB;
			/* TODO
			estab_peer_link(cand->peer_mac,
				cand->mtk, sizeof(cand->mtk),
				cand->mgtk, sizeof(cand->mgtk),
				cand->mgtk_expiration, cand->sup_rates,
				cand->sup_rates_len, cand->cookie);
			changed |= mesh_set_ht_op_mode(cand->conf->mesh);
			sae_debug(AMPE_DEBUG_FSM, "Mesh plink with "
				MACSTR " ESTABLISHED\n", MAC2STR(cand->peer_mac));
			*/
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;

	case PLINK_ESTAB:
		switch (next_state) {
		case CLS_ACPT:
			sta->plink_state = PLINK_HOLDING;
			/* TODO
			reason = htole16(MESH_CLOSE_RCVD);
			cand->reason = reason;
			cand->timeout = aconf->holding_timeout_ms;
			cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			changed |= mesh_set_ht_op_mode(cand->conf->mesh);
			*/
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;
	case PLINK_HOLDING:
		switch (next_state) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			break;
		case OPN_ACPT:
		case CNF_ACPT:
		case OPN_RJCT:
		case CNF_RJCT:
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		default:
            break;
		}
		break;
	default:
		wpa_msg(wpa_s, MSG_INFO, "Unsupported MPM transition: %d -> %d",
			sta->plink_state, next_state);
		break;
	}
/* TODO
	if (changed)
		meshd_set_mesh_conf(cand->conf->mesh, changed);
*/
}

void mesh_mpm_action_rx(struct wpa_supplicant *wpa_s,
			struct rx_action *rx_action)
{
	unsigned char action_field;
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct sta_info *sta;
	u16 plid = 0, llid = 0;
	enum plink_event event;
	struct ieee802_11_elems elems;
	struct mesh_peer_mgmt_ie peer_mgmt_ie;
	const u8 *ies;
	size_t ie_len;
	int ret;


	if (rx_action->category != WLAN_ACTION_SELF_PROTECTED)
		return;

	/* action code, mesh id and peering mgmt */
	if (rx_action->len < 1 + 2 + 2)
		return;

	action_field = rx_action->data[0];

	ies = rx_action->data + 1;
	ie_len = rx_action->len - 1;
	if (action_field == PLINK_OPEN || action_field == PLINK_CONFIRM) {
		ies += 2;	/* capability */
		ie_len -= 2;
	}
	if (action_field == PLINK_CONFIRM) {
		ies += 2;	/* aid */
		ie_len -= 2;
	}

	/* check for mesh peering, mesh id and mesh config IEs */
	if (ieee802_11_parse_elems(ies, ie_len, &elems, 0) == ParseFailed)
		return;
	if (!elems.peer_mgmt)
		return;
	if ((action_field != PLINK_CLOSE) &&
	    (!elems.mesh_id || !elems.mesh_config))
		return;

	ret = mesh_mpm_parse_peer_mgmt(wpa_s, action_field,
				       elems.peer_mgmt,
				       elems.peer_mgmt_len,
				       &peer_mgmt_ie);
	if (ret)
		return;

	/* the sender's llid is our plid and vice-versa */
	plid = WPA_GET_LE16(peer_mgmt_ie.llid);
	if (peer_mgmt_ie.plid)
		llid = WPA_GET_LE16(peer_mgmt_ie.plid);

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

	/* Now we will figure out the appropriate event... */
	switch (action_field) {
	case PLINK_OPEN:
		if (!plink_free_count() ||
		    (sta->peer_lid && sta->peer_lid != plid))
			event = OPN_IGNR;
		else {
			sta->peer_lid = plid;
			event = OPN_ACPT;
		}
		break;

	case PLINK_CONFIRM:
		if (!plink_free_count() ||
		    (sta->my_lid != llid || sta->peer_lid != plid))
			event = CNF_IGNR;
		else
			event = CNF_ACPT;
		break;

	case PLINK_CLOSE:
		if (sta->plink_state == PLINK_ESTAB)
			/* Do not check for llid or plid. This does not
			 * follow the standard but since multiple plinks
			 * per cand are not supported, it is necessary in
			 * order to avoid a livelock when MP A sees an
			 * establish peer link to MP B but MP B does not
			 * see it. This can be caused by a timeout in
			 * B's peer link establishment or B being
			 * restarted.
			 */
			event = CLS_ACPT;
		else if (sta->peer_lid != plid)
			event = CLS_IGNR;
		else if (peer_mgmt_ie.plid && sta->my_lid != llid)
			event = CLS_IGNR;
		else
			event = CLS_ACPT;
		break;
	default:
		wpa_msg(wpa_s, MSG_ERROR, "Mesh plink: unknown frame subtype\n");
		return;
	}
	mesh_mpm_fsm(wpa_s, sta, event);
}

