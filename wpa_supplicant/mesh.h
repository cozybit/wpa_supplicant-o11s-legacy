/*
 * WPA Supplicant - Basic mesh mode support
 * Copyright (c) 2013, Thomas Pedersen <thomas@cozybit.com>
 * Copyright (c) 2013, cozybit, Inc.
 *
 * All rights reserved.
 */

#ifndef MESH_H
#define MESH_H

#include "ap/hostapd.h"

/**
 * mesh_iface - per-interface mesh data
 */
struct mesh_iface {
	int num_bss;
	struct hostapd_data **bss;
	char *ies;
	int ie_len;
};

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, int ie_len);
void wpa_supplicant_mesh_iface_deinit(struct mesh_iface *ifmsh);
#endif /* MESH_H */
