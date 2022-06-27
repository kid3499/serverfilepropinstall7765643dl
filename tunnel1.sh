#!/usr/bin/env bash
###################################################################################
## X4B.Net Linux/BSD Tunnel Configurator
## Version: 1.9.1
## https://www.x4b.net/
##
## Meow
##
## Licence:
## Copyright (c) 2022, X4B
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
## 1. Redistributions of source code must retain the above copyright
##notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##notice, this list of conditions and the following disclaimer in the
##documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##must display the following acknowledgement:
##This product includes software developed by the X4B.
## 4. Neither the name of the X4B nor the
##names of its contributors may be used to endorse or promote products
##derived from this software without specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY X4B ''AS IS'' AND ANY
## EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
## WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL X4B BE LIABLE FOR ANY
## DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
## (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
## LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
## ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
## (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
## SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###################################################################################

## Global Config

# Configuration for NAT forwarding a GRE tunnel (i.e to a system that does not support GRE)
# Do not set UNLESS you know what this does, and how to use it.
GATEWAY_FORWARDING_ENABLED=0

# IP Address of the machine to receive forwarded packets
GATEWAY_FORWARDING_GATEWAY="192.168.245.1"

# Set to 1 to give X4B exclusive ownership of the fwmark & ctmark 0xff000000
# See https://www.x4b.net/kb/Tunnels for information on Exclusive Mode
X4B_EXCLUSIVE_MODE="0"

## Tunnel Entries


#If you are using NAT you will need to change this to reflect the NAT'ed address.
#GRE traffic should be directed to this IP address (e.g via NAT Router DMZ).
LOCAL_ADDR=62.210.246.173

#Proected IP Endpoint.
X4B_ADDR=45.35.192.103

#Internal IPs on this Endpoint.
INTERNAL_ADDR="10.16.0.26/30"
ROUTED_ADDR=""

#Network Specification.
NETWORK=10.16.0.24
NETWORK_CIDR=30

#Internal Gateway address.
GATEWAY=10.16.0.25
MTU=1472

#Tunnel type (gre/ipip).
TYPE=gre
KEY="4121271751"
UNIFIED=0
OUTERIP=4


## Default Routes
# Want certain traffic to be sent over a NAT'ed GRE/IP-in-IP tunnel? Heres one way to do it.

DEFAULT_ROUTE_PORTS_TCP="" #TCP ports for traffic to be sent over the tunnel
DEFAULT_ROUTE_PORTS_UDP="" #TCP ports for traffic to be sent over the tunnel
DEFAULT_ROUTE_MARK="4/4" # the packet mark to be used to mark traffic to be sent like this
DEFAULT_ROUTE_INTERFACE="gre1" # the default interface
DEFAULT_ROUTE_ADDR="" # the local address of the interface you wish to use as the default

# NOTE: need something more complex, e.g want to send traffic over different tunnels depending on the port or more complex selectors?
#   1. Any traffic that has the mark $DEFAULT_ROUTE_MARK will be sent over the tunnel selected.
#   2. You can create your own rules using a different mark for other tunnels
# See http://www.x4b.net/kb/ for more information

## Other
CONNECTION_AWARE_ROUTING=0
NTUN=1
TYPES_GRE=1
TYPES_IPIP=0


# Important!! Set to empty if you don't want to update this script & configuration automatically (on run).

# Important!! Make sure to disable auto update if you modify any aspect of this script including the above configuration.

AUTOUPDATE_URL="https://www.x4b.net/apiv2/Tunnel/script?tunnel_sgs=33932&tunnel_secret_key1=b9KsukiGVQczFLxa%2F5QKzzFkjOVyVfu62aclLdN%2FHAYRuw9dl3bPkHw6LM%2BjbqQ5&tunnel_secret_key2=ygJqx0ZREgs90TVkVGG39kC8hAvPvtuEP%2BBZMwa%2BX0k%3D"
# AUTOUPDATE_URL="";


## ------------------------------------------------------------ ##

BASH_PATH=$(whereis -b bash | awk '{print $2}')

if [ "x$BASH_VERSION" = "x" ]; then
if [ "x$BASH_PATH" = "x" ]; then
echo "The bash shell is required to run this script. On FreeBSD bash can be installed with the ports system with the command:"
echo "\"pkg_add -r bash\" or \"pkg install bash\""
echo ""
echo "Most Linux distributions include this package, consult your distribution documentation for installation instructions."
exit 2
else
${BASH_PATH} "$0" "$1"
exit $?
fi
fi

trap "exit 1" TERM
export TOP_PID=$$

function error_msg {
if [[ $(who am i) =~ \([-a-zA-Z0-9\.]+\)$ ]]; then
echo "$1"
elif [[ -z "$PS1" && -z "$SSH_CLIENT" && -z "$SSH_TTY" ]]; then
echo "$1"
logger "$1"
else
echo "$1"
fi

kill -s TERM ${TOP_PID}
}

function get_nvar {
foo="$1"
if [[ "$2" != "0" ]]; then
foo="$1$2"
fi
echo "${!foo}"
}

function check_reqs {
if ! which awk >/dev/null; then
echo "GNU Awk is required to run this script. You may need to install it with your package manager"
echo "e.g apt-get install awk"
error_msg "Please install Awk"
fi

if [[ ${TYPES_GRE} == "1" ]]; then
if [[ -f /proc/user_beancounters ]]; then
if [[ ! $(ip addr show gre0 | grep gre0) ]]; then
error_msg "Kernel ip_gre module not loaded or accessible. You may need to contact your VPS hosting company."
fi
fi

if [[ ${platform} == "freebsd" ]]; then
if [[ ! $(kldstat | grep if_gre.ko) ]]; then
echo "Kernel if_gre module not loaded. We will now try to load it."
kldload if_gre
fi
fi
fi

if [[ ${TYPES_IPIP} == "1" ]]; then
if [[ -f /proc/user_beancounters ]]; then
if [[ ! $(ip addr show tun0 | grep tun0) ]]; then
error_msg "Kernel ipip module not loaded or accessible. You may need to contact your VPS hosting company."
fi
fi
fi
}

function add_line {
if ! grep -q "$2" "$1"; then
echo "Adding line '$2' to $1";
echo -e "\n$2\n" >> "$1"
fi
}

platform='unknown'
unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
platform='linux'

# cruel to anyone who wants to use rp_filter
# But multiple tunnels with PBR need rp_filter disabled on the default route AND each PBR interface
# This is the easiest (most compatible) way to ensure this. Silly Linux.
echo 0 | tee /proc/sys/net/ipv4/conf/*/rp_filter > /dev/null
elif [[ "$unamestr" == 'FreeBSD' ]]; then
platform='freebsd'
else
error_msg "Unknown platform, possibly not supported. Exiting."
fi

SCRIPT="$0"

function do_update {
if [[ -z $AUTOUPDATE_URL ]]; then
return
fi

if [[ -z $(whereis -b wget | awk '{print $2}') ]]; then
return
fi

me=`basename "$0"`
if [[ $me == ".tunnel.sh" ]]; then
return
fi

if ! wget --quiet --output-document=.tunnel.sh.tmp "$AUTOUPDATE_URL" ; then
echo "Failed: Error while trying to wget new version! Skipping."
return
else
if [[ -f .tunnel.sh ]]; then
mv .tunnel.sh .tunnel.sh.bak
fi
mv .tunnel.sh.tmp .tunnel.sh
fi

bash .tunnel.sh $@
exit $?
}

function remove_tunnel {
# args: i, table_name dev
if [[ ${type} == "ipsec" ]]; then
CONFIG_FILE="/etc/ipsec.x4b/tunnel${i}.conf"
rm "$CONFIG_FILE"
else
ip tunnel del "$dev"
ip rule del table "$table_name"
ip route del table "$table_name"
fi
ip route flush cache 2> /dev/null > /dev/null
}

function find_table_id {
local used_tables=$(awk 'NF && $1!~/^#/ {print $1}' /etc/iproute2/rt_tables)

for i in {130..240}
do
if ! echo "$used_tables" | grep -q "$i"; then
echo "$i"
return
fi
done

error_msg "Unable to find a valid unused routing table ID"
}

function ip_rule_add {
if ! ip $1 rule | grep -q -F "$2"; then
if ! ip $1 rule | grep -q -F "lookup $3"; then
ip $1 rule add $2
else
error_msg "ip rules are in an invalid state, please either manually correct this or run this script from a fresh boot"
fi
else
echo "Skipped adding ip rules, already added"
fi
}

function find_dev {
local devprefix="$1"
if [[ "$platform" == "freebsd" ]]; then
if [[ "$devprefix" == "ipip" ]]; then
devprefix="gif"
fi
fi

if [[ "$platform" == "freebsd" ]]; then
while read -r line; do
local interface=$(ifconfig ${line})
if echo "$interface" | grep -q "$2 --> $3"; then
echo "$line"
return
fi
done <<< $(ifconfig -g "$devprefix")

for i in {1..99}; do
if ! ifconfig "$devprefix$i" 2> /dev/null > /dev/null; then
echo "$devprefix$i"
return
fi
done
else
local interface=$(ip tunnel | grep "remote $3" | grep "local $2" | grep "$devprefix" | awk '{print substr($1,1,length($1)-1)}')
if [[ -z "$interface" ]]; then
for i in {1..99}; do
if ! ip tunnel | grep -q "$devprefix$i"; then
echo "$devprefix$i"
return
fi
done
else
echo "$interface"
return
fi
fi

error_msg "unable to find a valid device to use"
}

function iptables_cmd {
if [[ "$1" == "4" ]]; then
echo "iptables"
elif [[ "$1" == "6" ]]; then
echo "ip6tables"
fi
}

function iptables_add_once_rule {
local cmd=$(iptables_cmd $1)
$cmd -D ${@:2} 2> /dev/null > /dev/null
$cmd -A ${@:2} 2> /dev/null > /dev/null
}

function iptables_add_once_chain {
local cmd=$(iptables_cmd $1)
$cmd -X ${@:2} 2> /dev/null > /dev/null
$cmd -N ${@:2} 2> /dev/null > /dev/null
}

function ping_min {
local key="$1"
local ip="$2"
local dev="$3"

local ms=$(ping "${ip}" -I "${dev}" -c 3 | awk -F '/' 'END {print $5}' | awk -F '.' '{print $1}')

local ms_key="ping_ms_${key}"
local dev_key="ping_dev_${key}"

if [ -z ${!ms_key} ]; then
eval "${ms_key}=1000"
eval "${dev_key}=${dev}"
fi

if [[ ${!ms_key} -gt $ms ]]; then
eval "${ms_key}=${ms}"
eval "${dev_key}=${dev}"
fi
}

function ip_add {
  local additional=""
  if [[ "$4" != "" ]]; then
  additional="peer $4"
  fi

  local net="$2"
  if [[ ! "$net" =~ / ]]; then
if [[ "$2" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  net="$2/32"
else
  net="$2/128"
fi
  fi
  ip $1 addr add "$net" dev "$3" $additional 2>&1 | grep -v 'RTNETLINK answers: File exists'
}

function start_tunnel {
# args: i, type, local_addr, X4B_ADDR, ipsec_psk, dev, key, mtu, key, gateway, network, network_cidr, internal_addr, routed_addr, outer_ip
local "${@}"
local table_name="X4B${i}"
local dev=$(find_dev "$type" "$local_addr" "$X4B_ADDR")
local poxix_inet="inet"
local ip_cmd_prefix=""
if [[ "$outer_ip" == "6" ]]; then
posix_inet="inet6"
ip_cmd_prefix="-6"
if [[ "${type}" != "ipsec" ]]; then
type="ip6$type"
fi
fi

local internal_addr=($internal_addr)
local routed_addr=($routed_addr)

local ip_cmd="ip addr"
if [[ "$platform" == "freebsd" ]]; then
ip_cmd="ifconfig"
fi

if ! ${ip_cmd} | grep -q "$local_addr"; then
error_msg "Unable to find $local_addr locally, are you using NAT? If this address is correct and you are using NAT update the LOCAL_ADDR with the attached address"
fi

if [[ "${type}" == "ipsec" ]]; then
if [[ "$platform" == "freebsd" ]]; then
echo "FreeBSD IPSec tunnel configuration is currently not automated"
echo "Want to help? We welcome contributions in this area."
elif [[ -z $(whereis -b ipsec | awk '{print $2}') ]]; then
echo "An IPSec service (either StrongSwan or OpenSwan) must be installed and working to use IPSec"
echo "This may not be possible on OpenVZ!"
else
if [[ ! -d /etc/ipsec.x4b ]]; then
mkdir /etc/ipsec.x4b
fi

if ! grep -q "include /etc/ipsec.x4b/*.conf" /etc/ipsec.conf; then
echo "include /etc/ipsec.x4b/*.conf" >> /etc/ipsec.conf
fi

{
echo "conn x4b-tunnel${i}";
echo "  left=${local_addr}";
echo "  leftsubnet=${internal_addr[0]}/32";
echo "  leftnexthop=%defaultroute";
echo "  right=${X4B_ADDR}";
echo "  rightsubnet=0.0.0.0/0";
echo "  rightnexthop=%defaultroute";
echo "  auto=start" >> "$CONFIG_FILE";
echo "  authby=secret" >> "$CONFIG_FILE";
echo "  type=tunnel";
} > "/etc/ipsec.x4b/tunnel${i}.conf"

if ! grep -q "${local_addr} ${X4B_ADDR} : PSK \"${ipsec_psk}\"" /etc/ipsec.secrets; then
echo "${local_addr} ${X4B_ADDR} : PSK \"${ipsec_psk}\"" >> /etc/ipsec.secrets
fi

PRIMARY_INTERFACE=$(ip route get "${X4B_ADDR}" from "${local_addr}" | grep -Po 'dev [a-zA-Z0-9]+' | awk '{print $2}')
for ip in "${internal_addr[@]}"; do
ip_add "$ip_cmd_prefix" "${ip}" "$PRIMARY_INTERFACE"
done

for ip in "${routed_addr[@]}"; do
ip_add "$ip_cmd_prefix" "${ip}" "$PRIMARY_INTERFACE"
done

service ipsec reload

ipsec up "x4b-tunnel${i}"
fi
else
ip link show "${dev}" 2>/dev/null > /dev/null
RES=$?

if [[ ${platform} == "freebsd" ]]; then
if [[ ${RES} == "0" ]]; then
echo "Tunnel ${dev} already added, removing."
ifconfig "${dev}" destroy
fi

ifconfig "${dev}" create

TCOMMAND="ifconfig ${dev} tunnel ${local_addr} ${X4B_ADDR} mtu ${mtu}"
if [[ -n "${key}" && ("${type}" == "gre" || "${type}" == "ip6gre") ]]; then
TCOMMAND="${TCOMMAND} grekey ${key}"
fi
else
local iptmode="add"
if [[ ${RES} == "0" ]]; then
iptmode="change"
fi

TCOMMAND="ip $ip_cmd_prefix tunnel $iptmode ${dev} mode ${type} local ${local_addr} remote ${X4B_ADDR} ttl 128"
if [[ -n "${key}" && ("${type}" == "gre" || "${type}" == "ip6gre") ]]; then
TCOMMAND="${TCOMMAND} key ${key}"
fi
TCOMMAND="${TCOMMAND} ttl 255"
fi
${TCOMMAND}

if [[ ${platform} != "freebsd" ]]; then
ip link set ${dev} group 13
fi

if [[ -n "$bgp_peer" ]]; then
ip_add "$ip_cmd_prefix" "${bgp_local}" "$dev" "${bgp_peer}"
fi

for ip in "${internal_addr[@]}"; do
if [[ ${platform} == "freebsd" ]]; then
ifconfig "${dev}" $posix_inet "${ip}" "${gateway}"

IF=$(route show 8.8.8.8 | grep interface | awk '{print $2}')
echo "pass out quick on $IF route-to (${dev} ${gateway}) from ${network}/${network_cidr}" >> /etc/x4b-anchor
echo "pass in quick on ${dev} reply-to (${dev} ${gateway}) from ${network}/${network_cidr}" >> /etc/x4b-anchor
else
ip_add "$ip_cmd_prefix" "${ip}" "$dev"
fi
done

for ip in "${routed_addr[@]}"; do
if [[ ${platform} == "freebsd" ]]; then
ifconfig "${dev}" $posix_inet "${ip}" "${gateway}"

IF=$(route show 8.8.8.8 | grep interface | awk '{print $2}')
echo "pass out quick on $IF route-to (${dev} ${gateway}) from ${network}/${network_cidr}" >> /etc/x4b-anchor
echo "pass in quick on ${dev} reply-to (${dev} ${gateway}) from ${network}/${network_cidr}" >> /etc/x4b-anchor
else
ip $ip_cmd_prefix addr add "${ip}" dev "$dev"
fi
done

if [[ ${platform} == "freebsd" ]]; then
ifconfig "${dev}" up
else
ip link set "${dev}" up
if [[ $(sysctl net.ipv4.conf.${dev}.rp_filter | awk '{print $3}') != "0" ]]; then
  sysctl net.ipv4.conf.${dev}.rp_filter=0 | grep -v net.ipv4.conf.${dev}.rp_filter
fi

ip link set dev "${dev}" mtu "${mtu}"
fi
fi
}

function start_routes {
# args: i, type, local_addr, X4B_ADDR, ipsec_psk, dev, key, mtu, key, gateway, network, network_cidr, internal_addr, routed_addr, outer_ip
local "${@}"
local table_name="X4B${i}"
local dev=$(find_dev "$type" "$local_addr" "$X4B_ADDR")
local ip_cmd_prefix=""
if [[ "$outer_ip" == "6" ]]; then
posix_inet="inet6"
ip_cmd_prefix="-6"
fi

local internal_addr=($internal_addr)
local routed_addr=($routed_addr)

if [[ "${type}" != "ipsec" ]]; then
if [[ ${platform} != "freebsd" ]]; then
if ! grep -E -q --text "[0-9]+ ${table_name}$" "/etc/iproute2/rt_tables"; then
echo "Adding $table_name routing table"
local table_id=$(find_table_id)
echo "${table_id} ${table_name}" >> /etc/iproute2/rt_tables
fi

local unified_var="ping_dev_${gateway//./_}"
if [[ "${unified}" == "0" || "${!unified_var}" == "${dev}" ]]; then
ip rule del prio 300
ip rule add $ip_cmd_prefix prio 300 from "${network}/${network_cidr}" lookup "${table_name}"
fi
current_table_route=$(ip route show table "${table_name}" | grep 'default via' | grep -v "dev ${dev}")
if [[ "$current_table_route" != "" ]]; then
# shellcheck disable=SC2086
ip route del $ip_cmd_prefix $current_table_route table "${table_name}"
fi
ip $ip_cmd_prefix route add default dev "${dev}" via "${gateway}" table "${table_name}" 2>&1 | grep -v 'RTNETLINK answers: File exists'
fi
fi

for ip in "${routed_addr[@]}"; do
if [[ ${platform} != "freebsd" ]]; then
  ip rule add $ip_cmd_prefix prio 300 from "${ip}" lookup "${table_name}"
fi
done

if [[ "$CONNECTION_AWARE_ROUTING" == "0" && -z "$bgp_peer" ]]; then
if [[ ${platform} == "freebsd" ]]; then
ETH_CHECK=$(route show "${gateway}" | grep interface | awk '{print $2}')
else
ETH_CHECK=$(ip $ip_cmd_prefix route get "${gateway}" | grep dev | awk '{print $3}')
fi
if [[ "${type}" != "ipsec" && "$ETH_CHECK" != "${dev}" ]]; then
ip $ip_cmd_prefix route show
error_msg "Tunnel route not successful. There is probably another interface on your server with a conflicting route. Can not continue."
fi
fi

# GATEWAY FORWARDING VM
if [[ "${GATEWAY_FORWARDING_ENABLED}" == "1" ]]; then
for ip in "${internal_addr[@]}"; do
iptables_add_once_rule "$outer_ip" POSTROUTING -t nat -s "${GATEWAY_FORWARDING_GATEWAY}/32" -j SNAT --to-source "${ip}"
iptables_add_once_rule "$outer_ip" PREROUTING -t nat -d "${ip}/32" -j DNAT --to-destination "${GATEWAY_FORWARDING_GATEWAY}"
done

iptables_add_once_rule "$outer_ip" FORWARD -d "${GATEWAY_FORWARDING_GATEWAY}/32" -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
ip $ip_cmd_prefix rule add from "${GATEWAY_FORWARDING_GATEWAY}" table "${table_id}"
fi
}

function setup_connection_aware_routing {
if [[ "$platform" == "freebsd" ]]; then
error_msg "Connection aware routing (required for Unified Tunnels) is not currently supported on FreeBSD."
fi

local dev
local table

iptables -F X4BPRE -t mangle
iptables -F X4BINP -t mangle
iptables -F X4BOUT -t mangle

to_delete=$(ip rule | grep "from all fwmark" | grep "lookup X4B" | awk '{print substr($1,1,length($1)-1)}')
while read -r line; do
if [[ -n $line ]]; then
ip rule del pref ${line}
fi
done <<< "$to_delete"

for ((f=0;f<NTUN;f++)); do
dev=$(find_dev $(get_nvar TYPE ${f}) $(get_nvar LOCAL_ADDR ${f}) $(get_nvar X4B_ADDR ${f}))
outer_ip=$(get_nvar OUTERIP ${f})

local ip_prefix=""
if [[ "$outer_ip" == "6" ]]; then
ip_prefix="-6"
fi

iptables_add_once_rule "$outer_ip" X4BINP -t mangle -i ${dev} -j CONNMARK --set-mark 0x$(printf "%02x" $((f+1)))000000/0xFF000000
ip $ip_prefix rule add prio 100 fwmark 0x$(printf "%02x" $((f+1)))000000/0xFF000000 table X4B$f

iptables_add_once_rule "$outer_ip" X4BPRE -t mangle -i 'gre+' -j X4BINP
iptables_add_once_rule "$outer_ip" X4BPRE -t mangle -i 'gre+' -j X4BOUT

local internal_addr=($(get_nvar INTERNAL_ADDR ${f}))
if [[ "$X4B_EXCLUSIVE_MODE" == "1" ]]; then
  iptables_add_once_rule "$outer_ip" X4BPRE -t mangle ! -i 'gre+' -m connmark ! --mark 0x00000000/0xFF000000 -j CONNMARK --restore-mark --nfmask 0x00FFFFFF --ctmask 0xFF000000

  for ip in "${internal_addr[@]}"; do
iptables_add_once_rule "$outer_ip" X4BOUT -t mangle -s "${ip}" -j CONNMARK --restore-mark --nfmask 0x00FFFFFF --ctmask 0xFF000000
  done
else
  for ip in "${internal_addr[@]}"; do
  iptables_add_once_rule "$outer_ip" X4BPRE -t mangle -m conntrack --ctorigdst "${ip}" --ctdir REPLY -j CONNMARK --restore-mark --nfmask 0x00FFFFFF --ctmask 0xFF000000
  iptables_add_once_rule "$outer_ip" X4BOUT -t mangle -s "${ip}" -j CONNMARK --restore-mark --nfmask 0x00FFFFFF --ctmask 0xFF000000
  done
fi
done
}

function tunnel_ao_ping {
if [[ "${CONNECTION_AWARE_ROUTING}" == "1" ]]; then
echo "Optimizing outgoing routes"
for ((f=0;f<NTUN;f++)); do
if [[ $(get_nvar UNIFIED ${f}) ]]; then
local gw=$(get_nvar GATEWAY ${f})
local dev=$(find_dev $(get_nvar TYPE ${f}) $(get_nvar LOCAL_ADDR ${f}) $(get_nvar X4B_ADDR ${f}))
ping_min "${gw//./_}" "${gw}" "${dev}"
fi
done

echo "NOTE: We recommend adding a cronjob for this script with an argument of \"adjust_outgoing\" for maximum redundancy if you make many outgoing connections"
fi
}

function tunnel_ao {
tunnel_ao_ping
setup_connection_aware_routing
}

function tunnel_version {
  ABSOLUTE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  head -n 20 "$ABSOLUTE_PATH" | grep Version | head -n1 | awk '{print $NF}'
}

function tunnel_setup {
bold=$(tput bold)
normal=$(tput sgr0)

echo "${bold}X4B Tunnel setup script "$(tunnel_version)"${normal}"

check_reqs
tunnel_detect_fw

echo "Also Note: This script does not adjust the configuration of your applications. You should ensure your applications are bound to 0.0.0.0 or the appropriate tunnel IP."

if [[ ${platform} == "freebsd" ]]; then
sysctl -w net.inet.ip.forwarding=1 > /dev/null 2>&1
else
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1
fi

if [[ ${platform} == "freebsd" ]]; then
if [[ ! -e /dev/pf ]]; then
if [[ ! $(kldstat | grep pf.ko) ]]; then
echo "Kernel pf module not loaded. We will now try to load it."
kldload pf
fi

if [[ $(pfctl -s info | grep "Status: Disabled") ]]; then
pfctl -e
fi

if [[ ! -e /dev/pf ]]; then
error_msg "PF must be installed and enabled to run this script"
fi
# pf_enable="YES"
# gateway_enable="YES"
fi

echo "# Do not edit - AUTO GENERATED" > /etc/x4b-anchor
add_line /etc/pf.conf "anchor x4b_anchor"
add_line /etc/pf.conf "load anchor x4b_anchor from \"/etc/x4b-anchor\""
fi

for ((f=0;f<NTUN;f++)); do
start_tunnel i="$f" type=$(get_nvar TYPE ${f}) local_addr=$(get_nvar LOCAL_ADDR ${f}) outer_ip=$(get_nvar OUTERIP ${f})  \
X4B_ADDR=$(get_nvar X4B_ADDR ${f}) ipsec_psk=$(get_nvar IPSEC_PSK ${f}) key=$(get_nvar KEY ${f}) unified=$(get_nvar UNIFIED ${f}) \
mtu=$(get_nvar MTU ${f}) key=$(get_nvar KEY ${f}) gateway=$(get_nvar GATEWAY ${f}) bgp_local=$(get_nvar BGPLOCAL ${f}) bgp_peer=$(get_nvar BGPPEER ${f}) \
network=$(get_nvar NETWORK ${f}) network_cidr=$(get_nvar NETWORK_CIDR ${f}) internal_addr="$(get_nvar INTERNAL_ADDR ${f})" \
routed_addr="$(get_nvar ROUTED_ADDR ${f})"
done

tunnel_ao_ping

for ((f=0;f<NTUN;f++)); do
start_routes i="$f" type=$(get_nvar TYPE ${f}) local_addr=$(get_nvar LOCAL_ADDR ${f}) outer_ip=$(get_nvar OUTERIP ${f})  \
X4B_ADDR=$(get_nvar X4B_ADDR ${f}) ipsec_psk=$(get_nvar IPSEC_PSK ${f}) key=$(get_nvar KEY ${f}) unified=$(get_nvar UNIFIED ${f}) \
mtu=$(get_nvar MTU ${f}) key=$(get_nvar KEY ${f}) gateway=$(get_nvar GATEWAY ${f}) bgp_peer=$(get_nvar BGPPEER ${f}) \
network=$(get_nvar NETWORK ${f}) network_cidr=$(get_nvar NETWORK_CIDR ${f}) internal_addr="$(get_nvar INTERNAL_ADDR ${f})" \
routed_addr="$(get_nvar ROUTED_ADDR ${f})"
done

if [[ "${CONNECTION_AWARE_ROUTING}" == "1" ]]; then
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
echo "This script requires a newer version of Bash. Please upgrade to atleast Bash 4.1"
else

iptables_add_once_chain 4 X4BINP -t mangle
iptables_add_once_chain 4 X4BPRE -t mangle
iptables_add_once_chain 4 X4BOUT -t mangle

iptables_add_once_rule 4 INPUT -t mangle -i 'gre+' -j X4BINP
iptables_add_once_rule 4 PREROUTING -t mangle -j X4BPRE
iptables_add_once_rule 4 OUTPUT -t mangle -j X4BOUT
iptables_add_once_rule 4 FORWARD -t mangle -j X4BOUT


iptables_add_once_chain 6 X4BINP -t mangle
iptables_add_once_chain 6 X4BPRE -t mangle
iptables_add_once_chain 6 X4BOUT -t mangle

iptables_add_once_rule 6 INPUT -t mangle -i 'gre+' -j X4BINP
iptables_add_once_rule 6 PREROUTING -t mangle -j X4BPRE
iptables_add_once_rule 6 OUTPUT -t mangle -j X4BOUT
iptables_add_once_rule 6 FORWARD -t mangle -j X4BOUT

setup_connection_aware_routing
fi
fi

# default routes
if [[ "${DEFAULT_ROUTE_PORTS_TCP}" != "" || "${DEFAULT_ROUTE_PORTS_UDP}" != "" ]]; then
local interface=$(ip addr | grep "${DEFAULT_ROUTE_ADDR}" | awk '{print $NF}')
iptables_add_once_rule 4 POSTROUTING -t nat -m mark --mark "${DEFAULT_ROUTE_MARK}" -o "$interface" -j SNAT --to-source "${DEFAULT_ROUTE_ADDR}"

if [[ "${DEFAULT_ROUTE_PORTS_TCP}" != "" ]]; then
local ports=($DEFAULT_ROUTE_PORTS_TCP)
for port in "${ports[@]}"; do
iptables_add_once_rule 4 OUTPUT -t mangle -p tcp --dport $port -j MARK --set-xmark ${DEFAULT_ROUTE_MARK}
done
fi

if [[ "${DEFAULT_ROUTE_PORTS_UDP}" != "" ]]; then
local ports=($DEFAULT_ROUTE_PORTS_udp)
for port in "${ports[@]}"; do
iptables_add_once_rule 4 OUTPUT -t mangle -p udp --dport $port -j MARK --set-xmark ${DEFAULT_ROUTE_MARK}
done
fi

table=$(ip route show table all | grep "dev ${DEFAULT_ROUTE_INTERFACE}" | grep table | grep default | head -n1 | awk '{print $NF}')
ip_rule_add "" "prio 100 fwmark "${DEFAULT_ROUTE_MARK}" lookup $table" $table
ip_rule_add "-6" "prio 100 fwmark "${DEFAULT_ROUTE_MARK}" lookup $table" $table
fi

ip route flush cache 2> /dev/null > /dev/null
echo "Tunnel Setup Complete"
echo "Need documentation on the tunnel script (including troubleshooting)? https://www.x4b.net/kb/Tunnels"
}

function tunnel_install {
mkdir "/var/x4b/"
cp "${SCRIPT}" /var/x4b/tunnel.sh
chmod +x /var/x4b/tunnel.sh

if [[ $platform == "linux" ]]; then
echo "#!/bin/bash" > /etc/init.d/x4b-tunnel
echo "### BEGIN INIT INFO" >> /etc/init.d/x4b-tunnel
echo "# Provides: x4b-tunnel" >> /etc/init.d/x4b-tunnel
echo "# Required-Start:  \$network" >> /etc/init.d/x4b-tunnel
echo "# Required-Stop:   \$network" >> /etc/init.d/x4b-tunnel
echo "# Default-Start:   2 3 4 5" >> /etc/init.d/x4b-tunnel
echo "# Default-Stop:   0 1 6" >> /etc/init.d/x4b-tunnel
echo "# Short-Description: Start X4B tunnel at boot time" >> /etc/init.d/x4b-tunnel
echo "# Description:Enable DDoS protected Tunnel." >> /etc/init.d/x4b-tunnel
echo "### END INIT INFO" >> /etc/init.d/x4b-tunnel
echo "/var/x4b/tunnel.sh" >> /etc/init.d/x4b-tunnel
chmod +x /etc/init.d/x4b-tunnel

if [[ -n $(whereis -b update-rc.d | awk '{print $2}') ]]; then
update-rc.d x4b-tunnel defaults
elif [[ -b $(whereis -b chkconfig | awk '{print $2}') ]]; then
chkconfig --add x4b-tunnel
chkconfig x4b-tunnel on
fi
else
echo "#!/bin/sh" > /etc/rc.d/x4btunnel
echo ". /etc/rc.subr" >> /etc/rc.d/x4btunnel
echo "name=\"x4btunnel\"" >> /etc/rc.d/x4btunnel
echo "start_cmd=\"\${name}_start\"" >> /etc/rc.d/x4btunnel
echo "stop_cmd=\":\"" >> /etc/rc.d/x4btunnel
echo "x4btunnel_start()" >> /etc/rc.d/x4btunnel
echo "{" >> /etc/rc.d/x4btunnel
echo "bash /var/x4b/tunnel.sh" >> /etc/rc.d/x4btunnel
echo "}" >> /etc/rc.d/x4btunnel
echo "load_rc_config \$name" >> /etc/rc.d/x4btunnel
echo "run_rc_command \"\$1\"" >> /etc/rc.d/x4btunnel
chmod +x /etc/rc.d/x4btunnel
add_line /etc/rc.conf "x4btunnel_enable=\"YES\""
fi
}

function ping_test {
echo -n $1": "
ping $1 -n -c 2 2> /dev/null > /dev/null
STATUS=$?
if [[ "$STATUS" == "0" ]]; then
echo -e "\e[92mOK\e[39m"
else
echo -e "\e[31mFAIL ($STATUS)\e[39m"
fi
}

function tunnel_status {
for ((f=0;f<NTUN;f++)); do
ping_test $(get_nvar X4B_ADDR ${f})

echo -n " - GATEWAY> "
ping_test $(get_nvar GATEWAY ${f})

local internal_addr=($(get_nvar INTERNAL_ADDR ${f}))
for ip in "${internal_addr[@]}"; do
echo -n " - LOCAL> "
ping_test "$ip"
done

local bgp_peer=$(get_nvar BGPPEER ${f})
if [[ -n "$bgp_peer" ]]; then
echo -n " - BGP PEER> "
ping_test "$bgp_peer"
fi

local bgp_local=$(get_nvar BGPLOCAL ${f})
if [[ -n "$bgp_local" ]]; then
echo -n " - BGP LOCAL> "
ping_test "$bgp_local"
fi
done
}

function tunnel_detect_fw {
  if [[ $(iptables-save | grep ufw | wc -l) != "0" ]]; then
echo "Firewall (UFW) detected. This script does not make firewall adjustments, you may need to do so."
return
  fi

  if [[ $(iptables-save | grep LOGDROPIN | wc -l) != "0" ]]; then
echo "Firewall (CSF) detected. This script does not make firewall adjustments, you may need to do so."
return
  fi

  if [[ $(iptables-save | grep fail2ban-ssh | wc -l) != "0" ]]; then
echo "Firewall (fail2ban) detected. This script does not make firewall adjustments, you may need to do so."
return
  fi

  nrules=$(iptables-save | grep -v X4B | grep -v gre | grep '\-A' | wc -l)
  if [[ "$nrules" != "0" ]]; then
echo "$nrules rules detected in iptables. This may be because you are running a firewall. This script does not make firewall adjustments. You may need to do so."
  else
if [[ $(whereis nft | grep bin | wc -l) != "0" ]]; then
  nft_chains=$(nft list chains | grep chain | grep -v X4B | grep -v ' PREROUTING \| INPUT \| FORWARD \| OUTPUT \| POSTROUTING' | wc -l)
  if [[ "$nft_chains" != "0" ]]; then
echo "$nft_chains chains detected in nftables. This may be because you are running a firewall. This script does not make firewall adjustments. You may need to do so."
  fi
fi

echo "Please Note: This script does not adjust any firewalls. If you are running any firewall you may need to configure it."
  fi
}

function tunnel_debug {
echo "=== SYS ==="
uname -a
lsb_release -a
echo "=== IFCONFIG ==="
ifconfig
echo "=== IP ADDR ==="
ip addr
echo "=== IP LINK ==="
ip link
echo "=== IP RULE ==="
ip rule
echo "=== IP ROUTE ==="
ip route
echo "=== NETSTAT ==="
netstat -ln
echo "=== PING (ENDPOINTS) ==="
for ((f=0;f<NTUN;f++)); do
ping $(get_nvar X4B_ADDR ${f}) -n -c 4 -w 1
done
echo "=== TRACEROUTE (ENDPOINTS) ==="
for ((f=0;f<NTUN;f++)); do
traceroute $(get_nvar X4B_ADDR ${f}) -n -w 2
done
echo "=== PING (GATEWAYS) ==="
for ((f=0;f<NTUN;f++)); do
ping $(get_nvar GATEWAY ${f}) -n -c 4 -w 1
done
echo "=== ROUTES (GATEWAYS) ==="
for ((f=0;f<NTUN;f++)); do
ip route get $(get_nvar GATEWAY ${f})
done
echo "=== ROUTES (ENDPOINTS) ==="
for ((f=0;f<NTUN;f++)); do
ip route get $(get_nvar X4B_ADDR ${f})
done
echo "=== IFCONFIG (AFTER PING) ==="
ifconfig
if [[ "${GATEWAY_FORWARDING_ENABLED}" == "1" ]]; then
echo "=== IPTABLES-SAVE ==="
iptables-save
fi

echo "=== FIREWALL DETECTION ==="
tunnel_detect_fw
}

do_update $@

case $1 in
status)
tunnel_status
;;
debug)
tunnel_debug
;;
install)
tunnel_install
;;
adjust_outgoing)
tunnel_ao
;;
setup)
tunnel_setup
;;

*)
tunnel_setup
;;

esac
