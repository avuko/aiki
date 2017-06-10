#!/usr/bin/env bash

for i in {1..6}; do
ssh trap${i} 'echo "fs.file-max = 2097152" >> /etc/sysctl.conf'
ssh trap${i} 'sysctl -p'

ssh trap${i} 'cat >> /etc/security/limits.conf <<EOF
*         hard    nofile      500000
*         soft    nofile      500000
root      hard    nofile      500000
root      soft    nofile      500000
EOF
'
ssh trap${i} 'kill -9 $(pgrep -f ./aiki-linux-amd64)'
scp aiki-linux-amd64 trap${i}:.
echo "log out and login to set new limits on trap${i}"
done
