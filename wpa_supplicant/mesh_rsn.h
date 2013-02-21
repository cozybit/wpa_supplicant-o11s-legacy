#ifndef MESH_RSN_H
#define MESH_RSN_H
#include "mesh_mpm.h"
#include "common/sae.h"

struct mesh_rsn {
	struct wpa_supplicant *wpa_s;
	struct wpa_authenticator *auth;
	u8 psk[SAE_PMK_LEN];
	u8 mgtk[16];
#ifdef CONFIG_SAE
	struct wpabuf *sae_token;
	int sae_group_index;
#endif /* CONFIG_SAE */
};

struct mesh_rsn *mesh_rsn_auth_init(struct wpa_supplicant *wpa_s,
				    struct mesh_conf *conf);
int mesh_rsn_auth_sae_sta(struct wpa_supplicant *wpa_s, struct sta_info *sta);
void mesh_rsn_get_pmkid(struct sta_info *sta, u8 *pmkid);
void mesh_rsn_init_ampe_sta(struct wpa_supplicant *wpa_s,
			    struct sta_info *sta);
#endif /* MESH_RSN_H */
