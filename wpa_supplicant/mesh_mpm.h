#ifndef MESH_MPM_H
#define MESH_MPM_H

/* notify MPM of new mesh peer to be inserted in MPM and driver */
void
wpa_mesh_new_mesh_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
		       struct ieee802_11_elems *elems);


#endif /* MESH_MPM_H */
