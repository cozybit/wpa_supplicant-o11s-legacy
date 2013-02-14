#ifndef MESH_MPM_H
#define MESH_MPM_H
#include "mesh.h"

/* notify MPM of new mesh peer to be inserted in MPM and driver */
void
wpa_mesh_new_mesh_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
		       struct ieee802_11_elems *elems);
void mesh_mpm_mgmt_rx(struct wpa_supplicant *wpa_s,
		      struct rx_mgmt *rx_mgmt);
void mesh_mpm_action_rx(struct wpa_supplicant *wpa_s,
			struct rx_action *rx_action);
void mesh_mpm_deinit(struct hostapd_iface *ifmsh);

#endif /* MESH_MPM_H */
