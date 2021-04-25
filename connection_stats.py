#!/usr/bin/env python3

import argparse
import sys
import struct
import socket
import codecs

### variables
# the dictionary to store data from /proc/net/
# the keys should correspond to the Linux path in /proc/net, e.g. /proc/net/tcp
net_stats = {}

# list of protocols to check
protos = []
supported_protos = [ "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6" ]
default_proto = 'tcp'

# variable for limiting (or not) the connection consumers in the output
conn_output_limit = 10 # would be the default limit

# connections states
conn_states = {
    '01' : 'ESTABLISHED',
    '02' : 'TCP_SYN_SENT',
    '03' : 'TCP_SYN_RECV',
    '04' : 'TCP_FIN_WAIT1',
    '05' : 'TCP_FIN_WAIT2',
    '06' : 'TCP_TIME_WAIT',
    '07' : 'TCP_CLOSE',
    '08' : 'TCP_CLOSE_WAIT',
    '09' : 'TCP_LAST_ACK',
    '0A' : 'TCP_LISTEN',
    '0B' : 'TCP_CLOSING',
    '0C' : 'TCP_NEW_SYN_RECV'
}
### end variables

### functions

def parse_args ():
    """ Argument parser"""
    global protos, default_proto, supported_protos, conn_output_limit

    parser = argparse.ArgumentParser (
        description = "Script to analyze connections and report usage",
        usage = "%(prog)s [--ver=tcp|tcp4|tcp6|udp|udp4|udp6|all] (default is " + default_proto + " which is tcp4 connections)"
    )
    parser.add_argument ("--ver", help="What to report: version of protocol tcp|tcp4|tcp6|udp|udp4|udp6 or all together)", default=default_proto)
    parser.add_argument ("--limit", help="How many top consumers to report; number or 'all')", default=conn_output_limit)
    args = parser.parse_args()

    # protocol versions
    if args.ver is None:
        protos = [ default_proto ] # default
    elif args.ver == "all":
        protos = [ "tcp", "tcp6", "udp", "udp6" ]
    elif args.ver == "tcp4":
        protos = [ "tcp" ]
    elif args.ver == "udp4":
        protos = [ "udp" ]
    elif args.ver not in supported_protos:
        print (args.ver + " is not supported. Supported list of protocols: " + " ".join(supported_protos))
        exit (2)
    else:
        protos = [args.ver]

    if args.limit is not None:
        if args.limit == "all":
            conn_output_limit = 0 # output all
        else:
            conn_output_limit = int(args.limit)

def hex_to_ipv4(addr):
    """ Convert /proc IPv4 hex address into standard IPv4 notation. """
    # Instead of codecs.decode(), we can just convert a 4 byte hex string to an integer directly using python radix conversion.
    # Basically, int(addr, 16) EQUALS:
    # aOrig = addr
    # addr = codecs.decode(addr, "hex")
    # addr = struct.unpack(">L", addr)
    # assert(addr == (int(aOrig, 16),))
    addr = int(addr, 16)

    # system native byte order, 4-byte integer
    addr = struct.pack("=L", addr)
    addr = socket.inet_ntop(socket.AF_INET, addr)
    return addr

def hex_to_ipv6(addr):
    """ Convert /proc IPv6 hex address into standard IPv6 notation. """
    # turn ASCII hex address into binary
    addr = codecs.decode(addr, "hex")

    # unpack into 4 32-bit integers in big endian / network byte order
    addr = struct.unpack('!LLLL', addr)

    # re-pack as 4 32-bit integers in system native byte order
    addr = struct.pack('@IIII', *addr)

    # now we can use standard network APIs to format the address
    addr = socket.inet_ntop(socket.AF_INET6, addr)
    return addr

def hex_to_int_to_str (hex):
    """ Convert hex to integer (port numbers) and return string as output"""
    return str(int(hex, 16))

def state_to_str (st):
    """ Connection state to string based on conn_states dictionary
    return Unknown if not defined in the list (future kernels could add more states)
    """
    global conn_states
    if conn_states.get(st) is None:
        return "Unknown_state"
    else:
        return conn_states[st]

def get_stats ( proto ):
    """
    get data from /proc filesystem the format with 4* Linux kernels is
    https://www.kernel.org/doc/html/latest//networking/proc_net_tcp.html
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    (0)sl              - entry
    (1)local_address   - local_ip:port
    (2)rem_address     - remote_ip:port
    (3)st              - connection state https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp_states.h
            for values refer to conn_states dictionary in the variables section
    (4)tx_queue        - transmit-queue
    (5)rx_queue        - receive queue
    tr              - timer_active
            0       no timer is pending
            1       retransmit-timer is pending
            2       another timer (e.g. delayed ack or keepalive) is pending
            3       this is a socket in TIME_WAIT state. Not all fields will contain data (or even exist)
            4       zero window probe timer is pending
    tm->when        - number of jiffies until timer expires
    retrnsmt        - number of unrecovered RTO timeouts
    uid             -
    """
    global net_stats, protos

# initialize dictionaries if don't exist
    if net_stats.get(proto) is None:
        net_stats[proto] = {}
        net_stats[proto]["remote_ip"] = {}
        net_stats[proto]["local_port"] = {}
        net_stats[proto]["remote_port"] = {}
        net_stats[proto]["states"] = {}

    with open("/proc/net/" + proto, "r") as stats:
        stats = stats.read().splitlines()
        stats = stats[1:] # drop header row

        for conn in stats:
            conn = conn.split()

            r_ip, r_port = conn[2].split(':') #(remote address is 3rd column (index #2)
            if net_stats[proto]["remote_ip"].get(r_ip) is None:
                net_stats[proto]["remote_ip"][r_ip] = 0
            if net_stats[proto]["remote_port"].get(r_port) is None:
                net_stats[proto]["remote_port"][r_port] = 0

            l_ip, l_port = conn[1].split(':') #(local address is 2rd column (index #1)
            if net_stats[proto]["local_port"].get(l_port) is None:
                net_stats[proto]["local_port"][l_port] = 0

            net_stats[proto]["remote_ip"][r_ip] += 1
            net_stats[proto]["remote_port"][r_port] += 1
            net_stats[proto]["local_port"][l_port] += 1

            # connection states , 4th column (index #3)
            st = conn[3]
            if net_stats[proto]["states"].get(st) is None:
                net_stats[proto]["states"][st] = 0
            net_stats[proto]["states"][st] += 1

def sort_dict_value (d):
    """ sort dictionary by value"""
    my_sorted = sorted(d.items(), key=lambda item: item[1], reverse=True)
    return my_sorted

def output_stats():
    """ final output """
    global net_stats, conn_output_limit

    for k in sorted(net_stats): #loop over existing keys passed through argparse, like tcp, udp
        for k2 in sorted(net_stats[k], reverse=True): # key #2, the remote_ip, port, states

            total = sum(net_stats[k][k2].values())
            uniq = len(net_stats[k][k2])
            print ("------------------ {} : {}: total {}; unique {} (key:count)------------------".format(k,k2,str(total),str(uniq)))

            limit = 0
            for k3, cnt in sort_dict_value(net_stats[k][k2]): # key # 3 which is value (say IP address) and cnt is the associated counter
                if limit+1 > conn_output_limit and conn_output_limit != 0:
                    break;

                if ( k2 == "local_port" or k2 == "remote_port" ):
                    print (" {} : {}".format(hex_to_int_to_str(k3),str(cnt)))
                elif k2 == "states":
                    print (" {} : {}".format(state_to_str(k3),str(cnt)))

                else:
                    if k == "tcp6":
                        print (" {} : {}".format(hex_to_ipv6(k3),str(cnt)))
                    else:
                        print (" {} : {}".format(hex_to_ipv4(k3),str(cnt)))
                limit += 1

### end functions

def main():
    parse_args()
    for v in protos:
        get_stats (v)

    output_stats ()

if __name__ == '__main__': main()
