/*
 * WPA Supplicant - Basic mesh mode support
 * Copyright (c) 2013, cozybit, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MESH_H
#define MESH_H
#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/uuid.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "common/ieee802_11_defs.h"
#include "config_ssid.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "notify.h"

#include "ap/sta_info.h"
#include "ap/hostapd.h"
#include "ap/ieee802_11.h"

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid);
void wpa_supplicant_leave_mesh(struct wpa_supplicant *wpa_s);
void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, int ie_len);
void wpa_supplicant_mesh_iface_deinit(struct hostapd_iface *ifmsh);
int mesh_deactivate_sta(struct hostapd_data *hapd,
			struct sta_info *sta, void *ctx);
#endif /* MESH_H */
