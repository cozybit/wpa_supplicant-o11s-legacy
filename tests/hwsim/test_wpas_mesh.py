#!/usr/bin/python
#
# wpa_supplicant AP mode tests
# Copyright (c) 2014, cozybit Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hostapd
import hwsim_utils

def check_scan(dev, params, other_started=False):
    if not other_started:
        dev.dump_monitor()
    id = dev.request("SCAN " + params)
    if "FAIL" in id:
        raise Exception("Failed to start scan")
    id = int(id)

    if other_started:
        ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"])
        if ev is None:
            raise Exception("Other scan did not start")
        if "id=" + str(id) in ev:
            raise Exception("Own scan id unexpectedly included in start event")

        ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
        if ev is None:
            raise Exception("Other scan did not complete")
        if "id=" + str(id) in ev:
            raise Exception("Own scan id unexpectedly included in completed event")

    ev = dev.wait_event(["CTRL-EVENT-SCAN-STARTED"])
    if ev is None:
        raise Exception("Scan did not start")
    if "id=" + str(id) not in ev:
        raise Exception("Scan id not included in start event")

    ev = dev.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
    if ev is None:
        raise Exception("Scan did not complete")
    if "id=" + str(id) not in ev:
        raise Exception("Scan id not included in completed event")

    res = dev.request("SCAN_RESULTS")

    if not res.find("[MESH]"):
  	raise Exception("Scan did not contain a MESH network")

def test_wpas_mesh_mode_support(dev):
    """wpa_supplicant MESH mode - open network"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")

def test_wpas_mesh_mode_scan(dev, apdev):

    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].select_network(id)  # TODO We should call the group_add instead!!

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].select_network(id)  # TODO We should call the group_add instead!!

    time.sleep(3)
    check_scan(dev[0], "use_id=1")

 
