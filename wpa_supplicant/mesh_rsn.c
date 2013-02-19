#include "mesh_rsn.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/wpa_ie.h"
#include "ap/wpa_auth.h"
#include "ap/wpa_auth_i.h"

static void auth_logger(void *ctx, const u8 *addr, logger_level level,
			const char *txt)
{
	if (addr)
		wpa_printf(MSG_DEBUG, "AUTH: " MACSTR " - %s",
			   MAC2STR(addr), txt);
	else
		wpa_printf(MSG_DEBUG, "AUTH: %s", txt);
}


static const u8 * auth_get_psk(void *ctx, const u8 *addr, const u8 *prev_psk)
{
	struct mesh_rsn *mesh_rsn = ctx;
	wpa_printf(MSG_DEBUG, "AUTH: %s (addr=" MACSTR " prev_psk=%p)",
		   __func__, MAC2STR(addr), prev_psk);
	if (prev_psk)
		return NULL;
	return mesh_rsn->psk;
}

static int auth_set_key(void *ctx, int vlan_id, enum wpa_alg alg,
			const u8 *addr, int idx, u8 *key, size_t key_len)
{
	struct mesh_rsn *mesh_rsn = ctx;
	u8 seq[6];

	os_memset(seq, 0, sizeof(seq));

	if (addr) {
		wpa_printf(MSG_DEBUG, "AUTH: %s(alg=%d addr=" MACSTR
			   " key_idx=%d)",
			   __func__, alg, MAC2STR(addr), idx);
	} else {
		wpa_printf(MSG_DEBUG, "AUTH: %s(alg=%d key_idx=%d)",
			   __func__, alg, idx);
	}
	wpa_hexdump_key(MSG_DEBUG, "AUTH: set_key - key", key, key_len);

	return wpa_drv_set_key(mesh_rsn->wpa_s, alg, addr, idx,
			       1, seq, 6, key, key_len);
	/* TODO: mark as authenticated and initiate peering */
}

static int
__mesh_rsn_auth_init(struct mesh_rsn *rsn, const u8 *addr)
{
	struct wpa_auth_config conf;
	struct wpa_auth_callbacks cb;

	wpa_printf(MSG_DEBUG, "AUTH: Initializing group state machine");

	os_memset(&conf, 0, sizeof(conf));
	conf.wpa = 2;
	conf.wpa_key_mgmt = WPA_KEY_MGMT_SAE;
	conf.wpa_pairwise = WPA_CIPHER_CCMP;
	conf.rsn_pairwise = WPA_CIPHER_CCMP;
	conf.wpa_group = WPA_CIPHER_CCMP;
	/* XXX: eh, no EAPOL? */
	conf.eapol_version = 0;
	conf.wpa_group_rekey = 600;

	os_memset(&cb, 0, sizeof(cb));
	cb.ctx = rsn;
	cb.logger = auth_logger;
	cb.get_psk = auth_get_psk;
	cb.set_key = auth_set_key;
	/*
	cb.for_each_sta = auth_for_each_sta;
	*/

	rsn->auth = wpa_init(addr, &conf, &cb);
	if (rsn->auth == NULL) {
		wpa_printf(MSG_DEBUG, "AUTH: wpa_init() failed");
		return -1;
	}

	/* XXX: init sae things here */

	wpa_init_keys(rsn->auth);

	return 0;
}

static void mesh_rsn_deinit(struct mesh_rsn *rsn)
{
	/* TODO: stuff */
}

struct mesh_rsn *mesh_rsn_auth_init(struct wpa_supplicant *wpa_s,
				    struct mesh_conf *conf)
{
	struct mesh_rsn *mesh_rsn;
	struct hostapd_data *bss = wpa_s->ifmsh->bss[0];

	mesh_rsn = os_zalloc(sizeof(*mesh_rsn));
	if (mesh_rsn == NULL)
		return NULL;
	mesh_rsn->wpa_s = wpa_s;

	if (__mesh_rsn_auth_init(mesh_rsn, wpa_s->own_addr) < 0) {
		mesh_rsn_deinit(mesh_rsn);
		return NULL;
	}

	bss->wpa_auth = mesh_rsn->auth;

	conf->ies = mesh_rsn->auth->wpa_ie;
	conf->ie_len = mesh_rsn->auth->wpa_ie_len;

	wpa_supplicant_rsn_supp_set_config(wpa_s, wpa_s->current_ssid);

	return mesh_rsn;
}

static int index_within_array(const int *array, int idx)
{
	int i;
	for (i = 0; i < idx; i++) {
		if (array[i] == -1)
			return 0;
	}
	return 1;
}

static int mesh_rsn_sae_group(struct wpa_supplicant *wpa_s,
			      struct sae_data *sae)
{
	int *groups = wpa_s->ifmsh->bss[0]->conf->sae_groups;

	/* Configuration may have changed, so validate current index */
	if (!index_within_array(groups, wpa_s->mesh_rsn->sae_group_index))
		return -1;

	for (;;) {
		int group = groups[wpa_s->mesh_rsn->sae_group_index];
		if (group < 0)
			break;
		if (sae_set_group(sae, group) == 0) {
			wpa_dbg(wpa_s, MSG_DEBUG, "SME: Selected SAE group %d",
				sae->group);
		       return 0;
		}
		wpa_s->mesh_rsn->sae_group_index++;
	}

	return -1;
}

struct wpabuf *
mesh_rsn_build_sae_commit(struct wpa_supplicant *wpa_s,
			  struct wpa_ssid *ssid, struct sta_info *sta)
{
	struct wpabuf *buf;
	int len;

	if (ssid->passphrase == NULL) {
		wpa_msg(wpa_s, MSG_DEBUG, "SAE: No password available");
		return NULL;
	}

	if (mesh_rsn_sae_group(wpa_s, sta->sae) < 0) {
		wpa_msg(wpa_s, MSG_DEBUG, "SAE: Failed to select group");
		return NULL;
	}

	if (sae_prepare_commit(wpa_s->own_addr, sta->addr,
			       (u8 *) ssid->passphrase,
			       os_strlen(ssid->passphrase), sta->sae) < 0) {
		wpa_msg(wpa_s, MSG_DEBUG, "SAE: Could not pick PWE");
		return NULL;
	}

	len = wpa_s->mesh_rsn->sae_token ?
		wpabuf_len(wpa_s->mesh_rsn->sae_token) : 0;
	buf = wpabuf_alloc(4 + SAE_COMMIT_MAX_LEN + len);
	if (buf == NULL)
		return NULL;

	sae_write_commit(sta->sae, buf, wpa_s->mesh_rsn->sae_token);

	return buf;
}

static void mesh_rsn_send_auth(struct wpa_supplicant *wpa_s,
			       const u8 *dst, const u8 *src,
			       u16 auth_transaction, u16 resp,
			       struct wpabuf *data)
{
	struct ieee80211_mgmt *auth;
	u8 *buf;
	size_t len;

	len = IEEE80211_HDRLEN + sizeof(auth->u.auth) + wpabuf_len(data);
	buf = os_zalloc(len);
	if (buf == NULL)
		return;

	auth = (struct ieee80211_mgmt *) buf;
	auth->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_AUTH);
	os_memcpy(auth->da, dst, ETH_ALEN);
	os_memcpy(auth->sa, src, ETH_ALEN);
	os_memcpy(auth->bssid, dst, ETH_ALEN);

	auth->u.auth.auth_alg = host_to_le16(WLAN_AUTH_SAE);
	auth->u.auth.auth_transaction = host_to_le16(auth_transaction);
	auth->u.auth.status_code = host_to_le16(resp);

	if (data)
		os_memcpy(auth->u.auth.variable,
			  wpabuf_head(data), wpabuf_len(data));

	wpa_msg(wpa_s, MSG_DEBUG, "authentication frame: STA=" MACSTR
		   " auth_transaction=%d resp=%d (IE len=%lu)",
		   MAC2STR(dst), auth_transaction,
		   resp, (unsigned long) wpabuf_len(data));
	if (wpa_drv_send_mlme(wpa_s, buf, len, 0) < 0)
		perror("send_auth_reply: send");

	os_free(buf);
}

/* initiate new SAE authentication with sta */
int mesh_rsn_auth_sae_sta(struct wpa_supplicant *wpa_s,
			  struct sta_info *sta)
{
	u16 resp = WLAN_STATUS_SUCCESS;
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	struct wpabuf *buf;
	int len;

	if (!sta->sae) {
		sta->sae = os_zalloc(sizeof(*sta->sae));
		if (sta->sae == NULL)
			return -1;
		sta->sae->state = SAE_NOTHING;
	}

	buf = mesh_rsn_build_sae_commit(wpa_s, ssid, sta);
	if (!buf)
		return -1;

	sta->sae->state = SAE_COMMITTED;

	wpa_msg(wpa_s, MSG_DEBUG,
		"AUTH: started authentication with SAE peer: "
		MACSTR, MAC2STR(sta->addr));

	wpa_supplicant_set_state(wpa_s, WPA_AUTHENTICATING);

	mesh_rsn_send_auth(wpa_s, sta->addr, wpa_s->own_addr,
			   SAE_COMMITTED, WLAN_STATUS_SUCCESS, buf);

	/* maybe MPM does this
	eloop_register_timeout(SME_AUTH_TIMEOUT, 0, sme_auth_timer, wpa_s,
			       NULL);
			       */
	wpabuf_free(buf);
	return 0;
}
