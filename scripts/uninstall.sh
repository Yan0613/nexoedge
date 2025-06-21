#!/bin/bash

# check for root permission
if [ $UID -ne 0 ]; then
    echo "Please run the script as root"
    exit 1
fi

# stop the service
systemctl stop ncloud-cifs
# remove the service
systemctl disable ncloud-cifs
# remove the service script
rm /etc/systemd/system/ncloud-cifs.service
# reload service daemon
systemctl daemon-reload

