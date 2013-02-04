/*
 * WPA Supplicant - Basic mesh mode support
 * Copyright (c) 2013, Thomas Pedersen <thomas@cozybit.com>
 * Copyright (c) 2013, cozybit, Inc.
 *
 * XXX: license?
 */

#ifndef MESH_H
#define MESH_H
int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
#endif /* MESH_H */
