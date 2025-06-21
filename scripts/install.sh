#!/bin/bash

# check for root permission
if [ $UID -ne 0 ]; then
    echo "Please run the script as root"
    exit 1
fi

# install the service script
cp ncloud-cifs.service /etc/systemd/system/
chmod +x /etc/systemd/system/ncloud-cifs.service

# register the service
systemctl daemon-reload
systemctl enable ncloud-cifs

# start the service
read -p "Start the service now (yes/no)? " on
if [ "$on" == "yes" ]; then
    echo "Start service now ..."
    systemctl start ncloud-cifs
else
    echo "To start the service: '# service ncloud-cifs start'"
fi

echo "To stop the service '# service ncloud-cifs stop'"
