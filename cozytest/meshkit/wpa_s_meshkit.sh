#!/bin/bash

cleanup() {
	sudo killall wpa_supplicant
	# clean up interface for next round of testing
	sudo iw $iface interface del
}

fail() {
	echo $@
	cleanup
	exit 1
}

wpa_s_cli() {
	sudo wpa_cli -p$wpa_s_ctl $@
}

while getopts ":i:sc" opt; do
	case $opt in
		i)
			iface=$OPTARG
			;;
		s)
			secure=1
			;;
		c)
			create=1
			;;
		*)
			echo "wrong argument"
			exit 1
			;;
	esac
done

# test the meshkit -> libwpa interface.
# MeshTest will simply call
# mesh <iface> <meshid> <psk> <channel>
#
# meshkit will use this through wpa_ctrl.h to trigger a wpa_supplicant mesh
# join. The Android platform will use the same interface as exported in
# android/hardware/libhardware_legacy/wifi/wifi.c.

# use ./$0 -i <iface> # to scan then join an open mesh
# or ./$0 -i <iface>  -c # create a new mesh << do this first
#
# use -s in the above two examples for secure mesh

meshid=bazooka
psk=seeeeecrit

sudo mesh $iface up
# give wpa_supplicant fork time to come up
sleep 1

# mesh $iface $meshid $chan $mesh_ttl $rssi_threshold $bcn_intvl $psk
if [ ! -z "$secure" ]; then
	sudo mesh $iface join $meshid 1 10 -80 1000 $psk
else
	sudo mesh $iface join $meshid 1 10 -80 1000
fi

if [ -z "$create" ]; then
	# wait and check for estab
	sleep 5
	sudo iw $iface station dump | grep ESTAB || fail "not in ESTAB!"
fi

read # leave creator idling here

cleanup
