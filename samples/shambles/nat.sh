#!/bin/sh

if [ 3 -gt "$#" ]; then
  echo "sudo $0 <ext if> <int if> <int net> [blacklist net]";
  exit
fi

if [ 4 -lt "$#" ]; then
  echo "sudo $0 <ext if> <int if> <int net> [blacklist net]";
  exit
fi

IPT="iptables"

$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -P INPUT ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT ACCEPT

$IPT -P INPUT DROP
$IPT -A INPUT -i lo -j ACCEPT

#allow established connections in
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -i $1 -o $2 -m state --state ESTABLISHED,RELATED -j ACCEPT


$IPT -A INPUT -i $2 -m state --state NEW -s $3 -j ACCEPT
if [ 4 -eq "$#" ]; then
  $IPT -A FORWARD -i $2 -o $1 -d $4 -j DROP
fi
$IPT -A FORWARD -i $2 -o $1 -s $3 -j ACCEPT

#nat
$IPT -t nat -A POSTROUTING -o $1 ! -d $3 -j MASQUERADE

#DROP by default
$IPT -A INPUT -j REJECT
$IPT -A FORWARD -j DROP

#enable routing in case it is disabled
echo 1 > /proc/sys/net/ipv4/ip_forward

