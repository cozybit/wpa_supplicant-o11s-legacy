#!/bin/bash

fail() {
	echo $@
	sudo killall wpa_supplicant
	exit 1
}

wpa_s_cli() {
	sudo wpa_cli -p$wpa_s_ctl $@
}

# test the meshkit -> libwpa interface.
# MeshTest will simply call
# mesh <iface> <meshid> <psk> <channel>
#
# meshkit will use this through wpa_ctrl.h to trigger a wpa_supplicant mesh
# join. The Android platform will use the same interface as exported in
# android/hardware/libhardware_legacy/wifi/wifi.c.

# use ./$0 <iface> # to scan then join a mesh
# or ./$0 <iface> create # create a new mesh << do this first
[ -z "$1" ] && { echo "need iface!"; exit 1; }
[ "$2" = "create" ] && create="yes"

iface=$1
meshid=bazooka
psk=seeeeecrit

sudo iw $iface mesh leave
sudo ip link set $iface up

# XXX: really need channel?
# mesh $iface $meshid $chan $mesh_ttl $rssi_threshold $bcn_intvl $psk
sudo mesh $iface up $meshid 1 10 -20 1000 $psk

sleep 5

if [ -z "$create" ]; then
	# check estab
	echo "station dump"
	sudo iw $iface station dump
	sudo iw $iface station dump | grep ESTAB || fail "not in ESTAB!"
fi

read

sudo killall wpa_supplicant
