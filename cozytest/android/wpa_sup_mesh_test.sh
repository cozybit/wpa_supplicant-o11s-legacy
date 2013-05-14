#!/bin/sh

[ -z "$1" ] && { echo "gimme a phone!"; exit 1; }
which adbs || { echo "needs adbs, get it from guillermo"; exit 1; }
phone="$1"
ip=11.11.11.`expr "$phone" : '[A-Z]*\([0-9]*\$\)'`
channel="5 HT40+"
meshif="mesh1"

# in case
adbs -s $phone remount
cat > wpa_sup_mesh.conf << EOF
#ap_scan=1 scan for existing networks first
#ap_scan=2 start BSS immediately
#key_mgmt=SAE
#psk="seeeecrit"
ap_scan=1
user_mpm=1
network={
        ssid="bazooka"
        mode=5
	key_mgmt=SAE
	psk="seeeecrit"
        frequency=2432
}
EOF

adbs -s $phone push wpa_sup_mesh.conf /system/

# remove existing meshif
adbs -s $phone shell iw $meshif interface del

# kill existing wpa_s HOPE THERE IS JUST ONE!!
pid=`adbs -s $phone shell ps | grep wpa_s | awk '{print $2}'`
adbs -s $phone shell kill $pid

# add 2nd mesh interface (1st is ctl)
adbs -s $phone shell iw mesh0 interface add $meshif type mp
# get existing (hopefully unique between 2 nodes) mac bytes
macbytes=`adbs -s $phone shell ip link show $meshif | grep ether | awk '{print $2}' | cut -f5-6 -d':'`
adbs -s $phone shell ip link set $meshif address 42:00:00:00:$macbytes
adbs -s $phone shell ip link set $meshif up
adbs -s $phone shell ip addr add $ip/24 dev $meshif
echo ping this: $ip

adbs -s $phone shell wpa_supplicant -i $meshif -c /system/wpa_sup_mesh.conf -dd &

adbs -s $phone logcat > /tmp/$phone.log &
echo logs in: /tmp/$phone.log
