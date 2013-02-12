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
 * mesh_conf - local MBSS state and settings
 */
struct mesh_conf {
	u8 meshid[MAX_SSID_LEN];
	u8 meshid_len;
	/* Active Path Selection Protocol Identifier */
	u8 mesh_pp_id;
	/* Active Path Selection Metric Identifier */
	u8 mesh_pm_id;
	/* Congestion Control Mode Identifier */
	u8 mesh_cc_id;
	/* Synchronization Protocol Identifier */
	u8 mesh_sp_id;
	/* Authentication Protocol Identifier */
	u8 mesh_auth_id;
};

/**
 * mesh_iface - per-interface mesh data
 */
struct mesh_iface {
	int num_bss;
	struct hostapd_data **bss;
	/* don't want to put this in hostapd_data right away... */
	struct mesh_conf *conf;
	char *ies;
	int ie_len;
};

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, int ie_len);
void wpa_supplicant_mesh_iface_deinit(struct mesh_iface *ifmsh);
#endif /* MESH_H */
