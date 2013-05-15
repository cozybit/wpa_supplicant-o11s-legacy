#!/bin/bash

fail() {
	echo $@
	sudo killall wpa_supplicant
	exit 1
}
# exercise the wpa_cli mesh interface. meshkit will use this through wpa_ctrl.h
# to trigger a wpa_supplicant mesh join. The Android platform will use the same
# interface as exported in android/hardware/libhardware_legacy/wifi/wifi.c.

# use ./$0 <iface> # to scan then join a mesh
# or ./$0 <iface> create # create a new mesh
[ -z "$1" ] && { echo "need iface!"; exit 1; }
[ "$2" = "create" ] && create="yes"

iface=$1
wpa_s_ctl="/tmp/wpa_supplicant.sock_$iface"
wpa_s_conf="/tmp/wpa_supplicant.conf_$iface"
meshid=bazooka
psk=seeeeecrit

cat > $wpa_s_conf << EOF
#ap_scan=1 scan for existing networks first
#ap_scan=2 start BSS immediately
ap_scan=2
user_mpm=1
ctrl_interface="$wpa_s_ctl"
network={
        ssid="$meshid"
        mode=5
	key_mgmt=SAE
	psk="$psk"
        frequency=2432
}
EOF

# iface must be up for scan or join
sudo ip link set $iface up
sudo iw $iface mesh leave

if [ ! -z "$create" ]; then
	# should actually just spawn a wpa_supplicant, and hand wpa_cli a network here?
	sudo wpa_supplicant -i$iface -C$wpa_s_ctl -c$wpa_s_conf -dd
else
	# hopefully user was smart enough to create the mesh first..
	sudo wpa_supplicant -i$iface -C$wpa_s_ctl -dd &
	sleep 1
	sudo wpa_cli -p$wpa_s_ctl scan
	sleep 1

	# grep for right meshid
	found=`sudo wpa_cli -p$wpa_s_ctl scan_results | grep $meshid`
	[ -z "$found" ] && fail "couldn't find peer mesh in scan results!"

	# emulate user selecting MBSS and entering PSK
	# similar to what android does
	sudo wpa_cli -p$wpa_s_ctl add_network
	sudo wpa_cli -p$wpa_s_ctl set_network 0 ssid ''\"$meshid\"''
	sudo wpa_cli -p$wpa_s_ctl set_network 0 psk ''\"$psk\"''
	sudo wpa_cli -p$wpa_s_ctl set_network 0 key_mgmt 'SAE'
	# XXX: yes we need to set the mode, does IBSS/infra?
	sudo wpa_cli -p$wpa_s_ctl set_network 0 mode '5'
	sudo wpa_cli -p$wpa_s_ctl enable_network 0

	# TODO: ok it'll connect, but won't change the channel yet

	read
	# say "connect" with right psk and key_mgmt
	# check estab
fi

sudo killall wpa_supplicant
