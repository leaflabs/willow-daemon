#!/bin/sh

iface=$1

if [ "xx" = "x${iface}x" ] ; then
    iface=eth0
fi

echo Reconfiguring interface $iface

export UDP_BUF_SIZE=16777216;
sudo /sbin/sysctl -w net.core.rmem_max=$UDP_BUF_SIZE net.core.wmem_max=$UDP_BUF_SIZE net.core.rmem_default=$UDP_BUF_SIZE net.core.wmem_default=$UDP_BUF_SIZE
sudo ethtool -G $iface rx 4096
sudo ifconfig $iface mtu 4096
