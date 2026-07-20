#!/bin/bash

# Downloading the MikroTik image
wget https://download.mikrotik.com/routeros/7.21.2/chr-7.21.2.img.zip -O chr.img.zip

# Unzipping the image
gunzip -c chr.img.zip > chr.img
sleep 5

# Mounting the image
mount -o loop,offset=33571840 chr.img /mnt
sleep 5

# Determining the primary disk device
DISK=$(lsblk | grep disk | cut -d ' ' -f 1 | head -n 1)
sleep 5

# Creating the autorun script with MikroTik commands
cat > /mnt/rw/autorun.scr <<EOF
:do {:delay 60s} on-error {}
:do {/ip dhcp-client/add add-default-route=yes use-peer-dns=yes use-peer-ntp=yes interface=ether0 dhcp-options=hostname,clientid} on-error {}
:do {/ip dhcp-client/add add-default-route=yes use-peer-dns=yes use-peer-ntp=yes interface=ether1 dhcp-options=hostname,clientid} on-error {}
:do {/ip dhcp-client/add add-default-route=yes use-peer-dns=yes use-peer-ntp=yes interface=ether2 dhcp-options=hostname,clientid} on-error {}
:do {/ip dhcp-client/add add-default-route=yes use-peer-dns=yes use-peer-ntp=yes interface=ether3 dhcp-options=hostname,clientid} on-error {}
:do {/ip dhcp-client/add add-default-route=yes use-peer-dns=yes use-peer-ntp=yes interface=ether4 dhcp-options=hostname,clientid} on-error {}
EOF
sleep 5

# Unmounting the image
umount /mnt
sleep 5

# Triggering kernel to dump its caches
echo u > /proc/sysrq-trigger
sleep 5

# Writing the image to the primary disk device
dd if=chr.img of=/dev/$DISK bs=4M oflag=sync
sleep 5

# Syncing file system
echo s > /proc/sysrq-trigger
sleep 5
echo "Rebooting..."

# Rebooting
echo b > /proc/sysrq-trigger
