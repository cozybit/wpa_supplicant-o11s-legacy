#ifndef MESH_RSN_H
#define MESH_RSN_H
#include "mesh_mpm.h"

struct mesh_rsn {
	struct wpa_supplicant *wpa_s;
	struct wpa_authenticator *auth;
	u8 psk[PMK_LEN];
};

struct mesh_rsn *mesh_rsn_auth_init(struct wpa_supplicant *wpa_s,
				    struct mesh_conf *conf);
#endif /* MESH_RSN_H */
