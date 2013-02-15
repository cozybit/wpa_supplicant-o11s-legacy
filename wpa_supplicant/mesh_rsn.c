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

	if (idx == 0) {
		/*
		 * In IBSS RSN, the pairwise key from the 4-way handshake
		 * initiated by the peer with highest MAC address is used.
		 */
		if (addr == NULL ||
		    os_memcmp(mesh_rsn->wpa_s->own_addr, addr, ETH_ALEN) < 0) {
			wpa_printf(MSG_DEBUG, "AUTH: Do not use this PTK");
			return 0;
		}
	}

	return wpa_drv_set_key(mesh_rsn->wpa_s, alg, addr, idx,
			       1, seq, 6, key, key_len);
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

	mesh_rsn = os_zalloc(sizeof(*mesh_rsn));
	if (mesh_rsn == NULL)
		return NULL;
	mesh_rsn->wpa_s = wpa_s;

	if (__mesh_rsn_auth_init(mesh_rsn, wpa_s->own_addr) < 0) {
		mesh_rsn_deinit(mesh_rsn);
		return NULL;
	}

	conf->ies = mesh_rsn->auth->wpa_ie;
	conf->ie_len = mesh_rsn->auth->wpa_ie_len;

	return mesh_rsn;
}

int mesh_rsn_auth_sae_sta(struct wpa_supplicant *wpa_s,
			  struct sta_info *sta)
{
	if (!sta->sae) {
		sta->sae = os_zalloc(sizeof(*sta->sae));
		if (sta->sae == NULL)
			return -1;
	}

	sta->sae->state = SAE_NOTHING;
	sta->sae->send_confirm = 0;
	wpa_msg(wpa_s, MSG_DEBUG,
		"AUTH: initializing authentication with SAE peer: "
		MACSTR, MAC2STR(sta->addr));
	return 0;
}
