/*
 * WPA Supplicant - Basic mesh mode support
 * Copyright (c) 2013, Thomas Pedersen <thomas@cozybit.com>
 * Copyright (c) 2013, cozybit, Inc.
 *
 * All rights reserved.
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
void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, int ie_len);
void wpa_supplicant_mesh_iface_deinit(struct hostapd_iface *ifmsh);
#endif /* MESH_H */
