#!/usr/bin/python
#
# wpa_supplicant mesh mode tests
# Copyright (c) 2014, cozybit Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()

import hwsim_utils

def check_mesh_scan(dev, params, other_started=False):
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

def check_mesh_join(dev):
    ev = dev.wait_event(["MESH-GROUP-STARTED"])
    if ev is None:
        raise Exception("Test exception: Couldn't join mesh")

def check_mesh_leave(dev):
    ev = dev.wait_event(["MESH-GROUP-REMOVED"])
    if ev is None:
        raise Exception("Test exception: Couldn't leave mesh")

def check_mesh_peer_connected(dev):
    ev = dev.wait_event(["MESH-PEER-CONNECTED"])
    if ev is None:
        raise Exception("Test exception: couldn't find a remote peer")

def test_wpas_mesh_mode_support(dev):
    """wpa_supplicant MESH network mode support"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].remove_network(id)

def test_wpas_mesh_mode_scan(dev):
    """wpa_supplicant MESH scan support"""
    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_join(dev[0])
    check_mesh_join(dev[1])

#    check_mesh_peer_connected(dev[0])
#    check_mesh_peer_connected(dev[1])

    # Check for Mesh scan
    check_mesh_scan(dev[0], "use_id=1")

    # TODO Should we modify the framework so we leave mesh after each test?
    # For now leave mesh for next test
    dev[0].mesh_group_remove()
    dev[1].mesh_group_remove()
    check_mesh_leave(dev[0])
    check_mesh_leave(dev[1])
 
def test_wpas_mesh_open(dev, apdev):

    id = dev[0].add_network()
    dev[0].set_network(id, "mode", "5")
    dev[0].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[0].set_network(id, "key_mgmt", "NONE")
    dev[0].set_network(id, "frequency", "2412")
    dev[0].mesh_group_add(id)

    id = dev[1].add_network()
    dev[1].set_network(id, "mode", "5")
    dev[1].set_network_quoted(id, "ssid", "wpas-mesh-open")
    dev[1].set_network(id, "key_mgmt", "NONE")
    dev[1].set_network(id, "frequency", "2412")
    dev[1].mesh_group_add(id)

    # Check for mesh joined
    check_mesh_join(dev[0])
    check_mesh_join(dev[1])

    # Check for peer connected
    check_mesh_peer_connected(dev[0])
    check_mesh_peer_connected(dev[1])
