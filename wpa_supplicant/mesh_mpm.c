/*
 * Copyright (c) 2013, cozybit, Inc.
 *
 * All right reserved.
 */
#include "mesh_mpm.h"
#include "mesh_rsn.h"

#include "eloop.h"
#include "ap.h"

/* TODO make configurable */
#define dot11MeshMaxRetries 10
#define dot11MeshRetryTimeout 1
#define dot11MeshConfirmTimeout 1
#define dot11MeshHoldingTimeout 1

static void
mesh_mpm_plink_open(struct wpa_supplicant *wpa_s, struct sta_info *sta);

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

static const char *mplstate[] = {
	[PLINK_LISTEN] = "LISTEN",
	[PLINK_OPEN_SENT] = "OPEN_SENT",
	[PLINK_OPEN_RCVD] = "OPEN_RCVD",
	[PLINK_CNF_RCVD] = "CNF_RCVD",
	[PLINK_ESTAB] = "ESTAB",
	[PLINK_HOLDING] = "HOLDING",
	[PLINK_BLOCKED] = "BLOCKED"
};

static const char *mplevent[] = {
	[PLINK_UNDEFINED] = "UNDEFINED",
	[OPN_ACPT] = "OPN_ACPT",
	[OPN_RJCT] = "OPN_RJCT",
	[OPN_IGNR] = "OPN_IGNR",
	[CNF_ACPT] = "CNF_ACPT",
	[CNF_RJCT] = "CNF_RJCT",
	[CNF_IGNR] = "CNF_IGNR",
	[CLS_ACPT] = "CLS_ACPT",
	[CLS_IGNR] = "CLS_IGNR"
};

#define mpl_dbg(wpa_s, sta, event) \
	wpa_msg(wpa_s, MSG_DEBUG, "MPM " MACSTR " state %s event %s",\
		       MAC2STR(sta->addr), mplstate[sta->plink_state],\
		       mplevent[event]);

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

/* generate an llid for a link and set to initial state */
static void mesh_mpm_init_link(struct wpa_supplicant *wpa_s,
			       struct sta_info *sta)
{
	u16 llid;

	os_get_random((u8 *) &llid, sizeof(llid));

	sta->my_lid = llid;
	sta->peer_lid = 0;
	sta->plink_state = PLINK_LISTEN;
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

	wpa_msg(wpa_s, MSG_DEBUG, "MPM set " MACSTR " into %d",
				  MAC2STR(sta->addr), state);
	if ((ret = wpa_drv_sta_add(wpa_s, &params)))
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to set " MACSTR ": %d",
			MAC2STR(sta->addr), ret);
	return;
}

void
mesh_mpm_deinit(struct hostapd_iface *ifmsh)
{
	struct hostapd_data *data = ifmsh->bss[0];

	/* TODO: notify peers we're leaving */
	/* TODO: deregister frames and events */

	hostapd_free_stas(data);
}

/* for mesh_rsn to indicate this peer has completed authentication, and we're
 * ready to start AMPE */
void
mesh_mpm_auth_peer(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	struct hostapd_data *data = wpa_s->ifmsh->bss[0];
	struct hostapd_sta_add_params params;
	struct sta_info *sta;
	int ret;

	sta = ap_get_sta(data, addr);
	if (!sta) {
		wpa_msg(wpa_s, MSG_ERROR, "no such mesh peer!\n");
		return;
	}

	/* TODO: should do nothing if this sta is already authenticated, but
	 * the AP code already sets this flag. */
	sta->flags |= WLAN_STA_AUTH;

	mesh_rsn_init_ampe_sta(wpa_s, sta);

	os_memset(&params, 0, sizeof(params));
	params.addr = sta->addr;
	params.flags = (WPA_STA_AUTHENTICATED | WPA_STA_AUTHORIZED);
	params.set = 1;

	wpa_msg(wpa_s, MSG_DEBUG, "MPM authenticating " MACSTR,
				  MAC2STR(sta->addr));
	if ((ret = wpa_drv_sta_add(wpa_s, &params)))
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to set " MACSTR ": %d",
			MAC2STR(sta->addr), ret);

	mesh_mpm_plink_open(wpa_s, sta);
}

void
wpa_mesh_new_mesh_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
		       struct ieee802_11_elems *elems)
{
	struct hostapd_sta_add_params params;
	/* struct wmm_information_element *wmm; */
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	struct hostapd_data *data = wpa_s->ifmsh->bss[0];
	struct sta_info *sta = ap_sta_add(data, addr);

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

	mesh_mpm_init_link(wpa_s, sta);

	/* insert into driver */
	os_memset(&params, 0, sizeof(params));
	params.supp_rates = sta->supported_rates;
	params.supp_rates_len = sta->supported_rates_len;
	params.addr = addr;
	params.plink_state = sta->plink_state;
	/* not used for mesh */
	params.aid = 1;
	params.listen_interval = 100;
	/* TODO: HT capabilities */
	/* TODO: flags? drv_flags? */
	params.flags |= WPA_STA_WMM;
	params.flags_mask |= WPA_STA_AUTHENTICATED;
	if (conf->security == MESH_CONF_SEC_NONE) {
		params.flags |= WPA_STA_AUTHORIZED;
		params.flags |= WPA_STA_AUTHENTICATED;
	} else {
		sta->flags |= WLAN_STA_MFP;
		params.flags |= WPA_STA_MFP;
	}

	//params.qosinfo = sta->qosinfo;
	if ((ret = wpa_drv_sta_add(wpa_s, &params))) {
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to insert " MACSTR ": %d",
			MAC2STR(addr), ret);
		return;
	}

	if (conf->security == MESH_CONF_SEC_NONE)
		mesh_mpm_plink_open(wpa_s, sta);
	else
		mesh_rsn_auth_sae_sta(wpa_s, sta);
}

static void mesh_mpm_send_plink_action(struct wpa_supplicant *wpa_s,
				       struct sta_info *sta,
				       enum plink_action_field type,
				       u16 close_reason)
{
	struct wpabuf *buf;
	struct hostapd_iface *ifmsh = wpa_s->ifmsh;
	struct hostapd_data *bss = ifmsh->bss[0];
	struct mesh_conf *conf = ifmsh->mconf;
	u8 supp_rates[2 + 2 + 32];
	u8 *pos, *cat;
	u8 ie_len, add_plid = 0;
	int ret;
	int ampe = conf->security & MESH_CONF_SEC_AMPE;

	buf = wpabuf_alloc(2 +      /* capability info */
			   2 +      /* AID */
			   2 + 8 +  /* supported rates */
			   2 + (32 - 8) +
			   2 + 32 + /* mesh ID */
			   2 + 7 +  /* mesh config */
			   2 + 26 + /* HT capabilities */
			   2 + 22 + /* HT operation */
			   2 + 23 + /* peering management */
			   2 + 96 + /* AMPE */
			   2 + 16); /* MIC */
	if (!buf)
		return;

	cat = wpabuf_head_u8(buf);
	wpabuf_put_u8(buf, WLAN_ACTION_SELF_PROTECTED);
	wpabuf_put_u8(buf, type);

	if (type != PLINK_CLOSE) {
		if (ampe)
			wpabuf_put_u8(buf, 0x10);
		else
			wpabuf_put_u8(buf, 0x0);
		wpabuf_put_u8(buf, 0);
		if (type == PLINK_CONFIRM)
			/* TODO: AID? */
			wpabuf_put_le16(buf, 0);
	}

	/* IE: supp + ext. supp rates */
	pos = hostapd_eid_supp_rates(bss, supp_rates);
	pos = hostapd_eid_ext_supp_rates(bss, pos);
	wpabuf_put_data(buf, supp_rates, pos - supp_rates);

	/* IE: Mesh ID */
	wpabuf_put_u8(buf, WLAN_EID_MESH_ID);
	wpabuf_put_u8(buf, conf->meshid_len);
	wpabuf_put_data(buf, conf->meshid, conf->meshid_len);

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
	if (ampe)
		ie_len += PMKID_LEN;
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
	/* peering protocol (le!) */
	if (ampe)
		wpabuf_put_u8(buf, 0x01);
	else
		wpabuf_put_u8(buf, 0x00);
	wpabuf_put_u8(buf, 0x0);
	if (sta)
		wpabuf_put_le16(buf, sta->my_lid);
	else
		wpabuf_put_le16(buf, 0);
	if (add_plid)
		wpabuf_put_le16(buf, sta->peer_lid);
	if (type == PLINK_CLOSE)
		wpabuf_put_le16(buf, close_reason);
	if (ampe)
		mesh_rsn_get_pmkid(sta, (u8 *) wpabuf_put(buf, PMKID_LEN));

	/* TODO HT IEs */

	if (ampe && mesh_rsn_protect_frame(wpa_s->mesh_rsn, sta, cat, buf)) {
		wpa_msg(wpa_s, MSG_INFO,
			"Mesh MPM: failed to add AMPE and MIC IE");
		goto fail;
	}

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0,
				sta->addr, wpa_s->own_addr, wpa_s->own_addr,
				wpabuf_head(buf), wpabuf_len(buf), 0);
	if (ret < 0)
		wpa_msg(wpa_s, MSG_INFO, "Mesh MPM: failed to send peering frame");

fail:
	wpabuf_free(buf);
}

void mesh_mpm_mgmt_rx(struct wpa_supplicant *wpa_s,
		      struct rx_mgmt *rx_mgmt)
{
	struct hostapd_frame_info fi;
	os_memset(&fi, 0, sizeof(fi));
	fi.datarate = rx_mgmt->datarate;
	fi.ssi_signal = rx_mgmt->ssi_signal;
	ieee802_11_mgmt(wpa_s->ifmsh->bss[0], rx_mgmt->frame,
			rx_mgmt->frame_len, &fi);
}

static void mesh_mpm_fsm_restart(struct wpa_supplicant *wpa_s,
				 struct sta_info *sta)
{
	wpa_mesh_set_plink_state(wpa_s, sta, PLINK_LISTEN);
	sta->my_lid = sta->peer_lid = sta->mpm_close_reason = 0;
	sta->mpm_retries = 0;
}

static void plink_timer(void *eloop_ctx, void *user_data)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct sta_info *sta = user_data;
	u16 reason = 0;

	switch (sta->plink_state) {
	case PLINK_OPEN_RCVD:
	case PLINK_OPEN_SENT:
		/* retry timer */
		if (sta->mpm_retries < dot11MeshMaxRetries) {
			eloop_register_timeout(dot11MeshRetryTimeout, 0, plink_timer, wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
			break;
		}
		reason = WLAN_REASON_MESH_MAX_RETRIES;
		/* fall through on else */

	case PLINK_CNF_RCVD:
		/* confirm timer */
		if (!reason)
			reason = WLAN_REASON_MESH_CONFIRM_TIMEOUT;
		sta->plink_state = PLINK_HOLDING;
		eloop_register_timeout(dot11MeshHoldingTimeout, 0, plink_timer, wpa_s, sta);
		mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
		break;
	case PLINK_HOLDING:
		/* holding timer */
		mesh_mpm_fsm_restart(wpa_s, sta);
		break;
	default:
		break;
	}
}

static void mesh_mpm_plink_estab(struct wpa_supplicant *wpa_s,
				 struct sta_info *sta)
{
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	u8 seq[6] = {};

	if (conf->security & MESH_CONF_SEC_AMPE) {
		/* key index != 0 is used to set key type */
		wpa_drv_set_key(wpa_s, WPA_ALG_CCMP, sta->addr, 0, 0,
				seq, sizeof(seq), sta->mtk, sizeof(sta->mtk));
		wpa_drv_set_key(wpa_s, WPA_ALG_CCMP, sta->addr, 4, 0,
				seq, sizeof(seq), sta->mgtk, sizeof(sta->mgtk));
		wpa_drv_set_key(wpa_s, WPA_ALG_IGTK, sta->addr, 4, 0,
				seq, sizeof(seq), sta->mgtk, sizeof(sta->mgtk));
	}

	wpa_mesh_set_plink_state(wpa_s, sta, PLINK_ESTAB);

	/* TODO
	changed |= mesh_set_ht_op_mode(cand->conf->mesh);
	*/
	wpa_msg(wpa_s, MSG_INFO, "mesh plink with "
		MACSTR " established\n", MAC2STR(sta->addr));
}

/* initiate peering with station */
static void
mesh_mpm_plink_open(struct wpa_supplicant *wpa_s, struct sta_info *sta)
{
	eloop_register_timeout(dot11MeshRetryTimeout, 0, plink_timer, wpa_s, sta);
	mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
	mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
	wpa_mesh_set_plink_state(wpa_s, sta, PLINK_OPEN_SENT);
}

static void mesh_mpm_fsm(struct wpa_supplicant *wpa_s, struct sta_info *sta,
			 enum plink_event next_state)
{
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	u16 reason = 0;

	mpl_dbg(wpa_s, sta, next_state);
	switch (sta->plink_state) {
	case PLINK_LISTEN:
		switch (next_state) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			break;
		case OPN_ACPT:
			mesh_mpm_plink_open(wpa_s, sta);
			break;
		default:
			break;
		}
		break;

	case PLINK_OPEN_SENT:
		switch (next_state) {
		case OPN_RJCT:
		case CNF_RJCT:
			reason = WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION;
		case CLS_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;
			eloop_register_timeout(dot11MeshHoldingTimeout, 0, plink_timer, wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			/* retry timer is left untouched */
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_OPEN_RCVD);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_CNF_RCVD);
			eloop_register_timeout(dot11MeshConfirmTimeout, 0, plink_timer, wpa_s, sta);
			break;
		default:
			break;
		}
		break;

	case PLINK_OPEN_RCVD:
		switch (next_state) {
		case OPN_RJCT:
		case CNF_RJCT:
			reason = WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION;
		case CLS_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;
			eloop_register_timeout(dot11MeshHoldingTimeout, 0, plink_timer, wpa_s, sta);
			sta->mpm_close_reason = reason;
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			if (conf->security & MESH_CONF_SEC_AMPE)
				mesh_rsn_derive_mtk(wpa_s, sta);
			mesh_mpm_plink_estab(wpa_s, sta);
			break;
		default:
			break;
		}
		break;

	case PLINK_CNF_RCVD:
		switch (next_state) {
		case OPN_RJCT:
		case CNF_RJCT:
			reason = WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION;
		case CLS_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;
			eloop_register_timeout(dot11MeshHoldingTimeout, 0, plink_timer, wpa_s, sta);
			sta->mpm_close_reason = reason;
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			mesh_mpm_plink_estab(wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;

	case PLINK_ESTAB:
		switch (next_state) {
		case CLS_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			reason = WLAN_REASON_MESH_CLOSE_RCVD;

			eloop_register_timeout(dot11MeshHoldingTimeout, 0, plink_timer, wpa_s, sta);
			/* TODO
			changed |= mesh_set_ht_op_mode(cand->conf->mesh);
			*/
			sta->mpm_close_reason = reason;
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
			reason = sta->mpm_close_reason;
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

	sta = ap_get_sta(hapd, rx_action->sa);
	if (!sta)
		return;
	/* TODO check peer is sae_accepted */

	if (!sta->my_lid)
		mesh_mpm_init_link(wpa_s, sta);

	/* TODO copy sup rates */

	mesh_rsn_process_ampe(wpa_s, sta, &elems);

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
