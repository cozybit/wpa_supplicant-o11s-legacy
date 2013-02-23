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
int mesh_rsn_derive_mtk(struct wpa_supplicant *wpa_s, struct sta_info *sta);
void mesh_rsn_get_pmkid(struct sta_info *sta, u8 *pmkid);
void mesh_rsn_init_ampe_sta(struct wpa_supplicant *wpa_s,
			    struct sta_info *sta);
int mesh_rsn_protect_frame(struct mesh_rsn *rsn,
			   struct sta_info *sta, const u8 *cat,
			   struct wpabuf *buf);
int mesh_rsn_process_ampe(struct wpa_supplicant *wpa_s,
			  struct sta_info *sta,
			  struct ieee802_11_elems *elems, const u8 *cat,
			  const u8 *start, size_t elems_len);
#endif /* MESH_RSN_H */
