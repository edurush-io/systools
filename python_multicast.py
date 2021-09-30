#!/usr/bin/env python3

"""
Send/receive UDP multicast packets
"""

import socket
import struct
import argparse

### variables 
cfg = {} # configuration used in the script
cfg['message'] = b'Hi, Multicast packet' # sample message 
cfg['multicast_ttl'] = 2 # hop limit, https://www.tldp.org/HOWTO/Multicast-HOWTO-6.html 
### end variables 

### functions

def parse_args ():
    parser = argparse.ArgumentParser (
        description = "Python multicast send/receive",
        usage = "%(prog)s --send|--receive --ip=MCAST_IP --port=MCAST_PORT"
    )
    parser.add_argument ("--ip", help="IP for Multicast Group", required=True)
    parser.add_argument ("--port", type=int, help="Port for Multicast Group", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument ("--send", help="Send multicast", action="store_true", default=False)
    group.add_argument ("--receive", help="Receive multicast", action="store_true", default=False)
    parser.add_argument ("--message", help="Message for Multicast Group (optional)", required=False)
    args = parser.parse_args()

    cfg['ip'] = args.ip
    cfg['port'] = args.port

    if args.send:
        cfg['action'] = 'send'
    else:
        cfg['action'] = 'receive'
    if args.message is not None:
        cfg['message'] = bytes(args.message, 'utf-8')

def mc_send ():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, cfg['multicast_ttl'])
    sock.sendto(cfg['message'], (cfg['ip'], cfg['port']))
    sock.close()

def mc_receive ():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg['ip'], cfg['port']))
    mreq = struct.pack('4sl', socket.inet_aton(cfg['ip']), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    while True:
        print(sock.recv(10240))

if __name__ == "__main__":
    parse_args()
    if cfg['action'] == 'send':
        print ("Sending multicast to {}:{}". format(cfg['ip'],cfg['port']))
        mc_send()
    else:
        print ("Listening for multicast on {}:{}".format(cfg['ip'],cfg['port']))
        mc_receive()
