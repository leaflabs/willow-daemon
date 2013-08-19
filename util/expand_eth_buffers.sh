#!/bin/sh

export UDP_BUF_SIZE=16777216;
sudo /sbin/sysctl -w net.core.rmem_max=$UDP_BUF_SIZE net.core.wmem_max=$UDP_BUF_SIZE net.core.rmem_default=$UDP_BUF_SIZE net.core.wmem_default=$UDP_BUF_SIZE
sudo ethtool -G eth0 rx 4096
sudo ifconfig eth0 mtu 4096
