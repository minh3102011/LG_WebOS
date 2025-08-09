#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run with sudo or as root."
   exit 1
fi
echo "Checking disk..."
if ! lsblk | grep -q '^sda'; then
   echo "/dev/sda does not exist"
   exit 1
fi
partitions=$(lsblk -r -n -o NAME | grep '^sda[0-9]')
if [ -z "$partitions" ]; then
   echo "No partitions found on /dev/sda"
   exit 1
fi
echo "Unmounting partition..."
for partition in $partitions; do
  partition_path="/dev/$partition"
  echo "Unmounting $partition_path..."

  if mount | grep -q "$partition_path"; then
     sudo umount "$partition_path"
  fi
done
echo "Unmounted all partitions. Deleting..."
sudo fdisk /dev/sda <<EOF
o
w
EOF

echo "Deleted all partitions. Flashing..."
sudo dd bs=4M if=/media/lg-lab-pc-15/DATA/TTTN/webos-image-raspberrypi4-64.rootfs.wic of=/dev/sda status=progress
echo "Done!"
