#!/usr/bin/env bash
#===============================================================================
#          FILE: openvpn.sh
#
#         USAGE: ./openvpn.sh
#
#   DESCRIPTION: Entrypoint for openvpn docker container
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: David Personette (dperson@gmail.com),
#  ORGANIZATION:
#       CREATED: 09/28/2014 12:11
#      REVISION: 1.0
#===============================================================================

set -o nounset                              # Treat unset variables as an error

### firewall: firewall all output not DNS/VPN that's not over the VPN connection
# Arguments:
#   none)
# Return: configured firewall
firewall() { local port="${1:-1194}" docker_network="$(ip -o addr show dev eth0 |
            awk '$3 == "inet" {print $4}')" network docker6_network="$(ip -o addr show dev eth0 |
            awk '$3 == "inet6" {print $4; exit}')"
    [[ -z "${1:-""}" && -r $conf ]] && port="$(awk '/^remote / && NF ~ /^[0-9]*$/ {print $NF}' $conf | grep ^ || echo 1194)"

    ip6tables -F OUTPUT 2>/dev/null
    ip6tables -P OUTPUT DROP 2>/dev/null
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o tap0 -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o tun0 -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -d ${docker6_network} -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    ip6tables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null ||
        { ip6tables -A OUTPUT -p tcp -m tcp --dport $port -j ACCEPT 2>/dev/null
        ip6tables -A OUTPUT -p udp -m udp --dport $port -j ACCEPT 2>/dev/null; }
    iptables -F OUTPUT
    iptables -P OUTPUT DROP
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tap0 -j ACCEPT
    iptables -A OUTPUT -o tun0 -j ACCEPT
    iptables -A OUTPUT -d ${docker_network} -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT || {
        iptables -A OUTPUT -p tcp -m tcp --dport $port -j ACCEPT
        iptables -A OUTPUT -p udp -m udp --dport $port -j ACCEPT; }
    [[ -s $route6 ]] && for net in $(cat $route6); do return_route6 $net; done
    [[ -s $route ]] && for net in $(cat $route); do return_route $net; done
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route6() { local network="$1" gw="$(ip -6 route | awk '/default/{print $3}')"
    ip -6 route | grep -q "$network" || ip -6 route add to $network via $gw dev eth0
    ip6tables -A OUTPUT --destination $network -j ACCEPT 2>/dev/null
    [[ -e $route6 ]] &&grep -q "^$network\$" $route6 ||echo "$network" >>$route6
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route() { local network="$1" gw="$(ip route | awk '/default/ {print $3}')"
    ip route | grep -q "$network" || ip route add to $network via $gw dev eth0
    iptables -A OUTPUT --destination $network -j ACCEPT
    [[ -e $route ]] && grep -q "^$network\$" $route || echo "$network" >>$route
}

### vpnportforward: setup vpn port forwarding
# Arguments:
#   port) forwarded port
# Return: configured NAT rule
vpnportforward() { local port="$1"
    ip6tables -t nat -A OUTPUT -p tcp --dport $port -j DNAT --to-destination ::11:$port 2>/dev/null
    iptables  -t nat -A OUTPUT -p tcp --dport $port -j DNAT --to-destination 127.0.0.11:$port
    echo "Setup forwarded port: $port"
}

### usage: Help
# Arguments:
#   none)
# Return: Help text
usage() { local RC="${1:-0}"
    echo "Usage: ${0##*/} [-opt] [command]
Options (fields in '[]' are optional, '<>' are required):
    -h          This help
    -f '[port]' Firewall rules so that only the VPN and DNS are allowed to
                send internet traffic (IE if VPN is down it's offline)
                optional arg: [port] to use, instead of default
    -p '<port>' Forward port <port>
                  required arg: '<port>'
    -R '<network>' CIDR IPv6 network (IE fe00:d34d:b33f::/64)
                required arg: '<network>'
                <network> add a route to (allows replies once the VPN is up)
    -r '<network>' CIDR network (IE 192.168.1.0/24)
                required arg: '<network>'
                <network> add a route to (allows replies once the VPN is up)

The 'command' (if provided and valid) will be run instead of openvpn" >&2
    exit $RC
}

dir="/vpn"
route="$dir/.firewall"
route6="$dir/.firewall6"

while getopts ":hc:f:p:R:r:" opt; do
    case "$opt" in
        h) usage ;;
        f) firewall "$OPTARG"; touch $route $route6 ;;
        p) vpnportforward "$OPTARG" ;;
        R) return_route6 "$OPTARG" ;;
        r) return_route "$OPTARG" ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ "${FIREWALL:-""}" || -e $route6 || -e $route ]] && [[ "${4:-""}" ]] && firewall $port
[[ "${FIREWALL:-""}" || -e $route ]] && firewall "${FIREWALL:-""}"
[[ "${ROUTE6:-""}" ]] && return_route6 "$ROUTE6"
[[ "${ROUTE:-""}" ]] && return_route "$ROUTE"
[[ "${VPN:-""}" ]] && eval vpn $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $VPN)
[[ "${VPNPORT:-""}" ]] && vpnportforward "$VPNPORT"
[[ "${GROUPID:-""}" =~ ^[0-9]+$ ]] && groupmod -g $GROUPID -o vpn

if [[ $# -ge 1 && -x $(which $1 2>&-) ]]; then
    exec "$@"
elif [[ $# -ge 1 ]]; then
    echo "ERROR: command not found: $1"
    exit 13
elif ps -ef | egrep -v 'grep|openvpn.sh' | grep -q openvpn; then
    echo "Service already running, please restart container to apply changes"
else
    mkdir -p /dev/net
    [[ -c /dev/net/tun ]] || mknod -m 0666 /dev/net/tun c 10 200
    exec sg vpn -c "openvpn --cd $dir --config $conf"
fi