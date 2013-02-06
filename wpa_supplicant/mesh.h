/*
 * WPA Supplicant - Basic mesh mode support
 * Copyright (c) 2013, Thomas Pedersen <thomas@cozybit.com>
 * Copyright (c) 2013, cozybit, Inc.
 *
 * All rights reserved.
 */

#ifndef MESH_H
#define MESH_H

struct meshd_data {
	int max_num_sta;
	int num_sta; /* number of entries in sta_list */
	struct sta_info *sta_list; /* STA info list head */
#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])
	struct sta_info *sta_hash[STA_HASH_SIZE];
};

/**
 * mesh_iface - per-interface mesh data
 */
struct mesh_iface {
	struct meshd_data *bss;
	char *ies;
	int ie_len;
};

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, int ie_len);
void wpa_supplicant_mesh_iface_deinit(struct mesh_iface *ifmsh);
#endif /* MESH_H */
