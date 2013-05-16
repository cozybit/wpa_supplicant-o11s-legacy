#!/bin/bash

fail() {
	echo $@
	sudo killall wpa_supplicant
	exit 1
}

wpa_s_cli() {
	sudo wpa_cli -p$wpa_s_ctl $@
}

# exercise the wpa_cli mesh interface. meshkit will use this through wpa_ctrl.h
# to trigger a wpa_supplicant mesh join. The Android platform will use the same
# interface as exported in android/hardware/libhardware_legacy/wifi/wifi.c.

# use ./$0 <iface> # to scan then join a mesh
# or ./$0 <iface> create # create a new mesh << do this first
[ -z "$1" ] && { echo "need iface!"; exit 1; }
[ "$2" = "create" ] && create="yes"

iface=$1
wpa_s_ctl="/tmp/wpa_supplicant.sock_$iface"
wpa_s_conf="/tmp/wpa_supplicant.conf_$iface"
meshid=bazooka
psk=seeeeecrit

sudo iw $iface mesh leave

# spawn wpa_supplicant on boot / when framework turns on android
# XXX: should be able to do this without an initial interface? It's fine,
# meshkit can launch this
sudo wpa_supplicant -C$wpa_s_ctl -i$iface -dd &
sleep 1

# need to be up for scan / mesh join
sudo ip link set $iface up

# we can add the network block immediately, the interface for joining or
# creating is the same. MeshTest will call:
# mesh <iface> <meshid> <channel>
# so all we have are those ^^. need psk
wpa_s_cli add_network
wpa_s_cli set_network 0 ssid ''\"$meshid\"''
wpa_s_cli set_network 0 psk ''\"$psk\"''
wpa_s_cli set_network 0 key_mgmt 'SAE'
# XXX: yes we need to set the mode, does IBSS/infra?
wpa_s_cli set_network 0 mode '5'

if [ ! -z "$create" ]; then
	# don't scan before joining
	wpa_s_cli set ap_scan=2
	wpa_s_cli set_network 0 frequency '2437'
else
	# do scan before joining
	wpa_s_cli set ap_scan=1
fi

wpa_s_cli enable_network 0

if [ -z "$create" ]; then
	# time for scanning
	sleep 2
	# grep for right meshid
	found=`wpa_s_cli scan_results | grep $meshid`
	[ -z "$found" ] && fail "couldn't find peer mesh in scan results!"
	sleep 3
	# check estab
	sudo iw $iface station dump | grep ESTAB || fail "not in ESTAB!"
fi

read

sudo killall wpa_supplicant
