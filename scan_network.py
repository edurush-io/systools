#!/usr/bin/env python3 

""" script for quick scanning of an IP range """

import ipaddress
import time
import struct
import select
import socket
import argparse
import concurrent.futures
import random

# variables
# where we would keep IPs 
ip_list = []

# cidr block
cidr = ''

# how many threads we are going to use
n_threads = 100
timeout = 1 # seconds 
# the below values will take place when "--fast" argument is given
fast_threads = 500
fast_timeout = 0.5
# the below values will take place when "--ufast" argument is given ### be careful with these :) 
ufast_threads = 1000
ufast_timeout = 0.3

# counters for quick summary
total_up = 0
total_down = 0
total_unknown = 0

# end variables 

### functions 
def icmp_checksum(data):
    x = sum(x << 8 if i % 2 else x for i, x in enumerate(data)) & 0xFFFFFFFF
    x = (x >> 16) + (x & 0xFFFF)
    x = (x >> 16) + (x & 0xFFFF)
    return struct.pack('<H', ~x & 0xFFFF)

def icmp_ping(addr, timeout=1, count=1, data=b''):
    global total_up, total_down, total_unknown
# from https://gist.github.com/pyos/10980172 
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as conn:
        payload = struct.pack('!HH', random.randrange(0, 65536), count) + data
        try: 
            conn.connect((addr, 1))
        except:
            print ("Please check network address " + addr)
            return False
        try:
            conn.sendall(b'\x08\0' + icmp_checksum(b'\x08\0\0\0' + payload) + payload)
        except:
            total_unknown += 1
        start = time.time()

        while select.select([conn], [], [], max(0, start + timeout - time.time()))[0]:
            data = conn.recv(65536)
            if len(data) < 20 or len(data) < struct.unpack_from('!xxH', data)[0]:
                continue
            if data[20:] == b'\0\0' + icmp_checksum(b'\0\0\0\0' + payload) + payload:
                total_up += 1
                print (addr + " is Up")
                return
        total_down += 1
        print (addr + " is Down")

def cidr_to_list (s):
    try:
        obj = ipaddress.ip_network(s)
    except ValueError as err:
        print (err)
        exit(2)
    for i in obj.hosts():
        ip_list.append(str(i))

### end functions

def parse_args ():
    global cidr, n_threads, timeout, max_n_threads, min_timeout
    """ Argument parser"""
    parser = argparse.ArgumentParser ( 
        description = "Quick network CIDR scanner", 
        usage = "%(prog)s CIDR (e.g. abc.def.gh.yz/nn)"
    )
    parser.add_argument ("cidr", help="CIDR block")
    parser.add_argument ("--fast", help="make it faster", action="store_true", default=False)
    parser.add_argument ("--ufast", help="ultra fast", action="store_true", default=False)

    args = parser.parse_args()
    cidr = args.cidr

    if args.fast == True:
        n_threads = fast_threads
        timeout = fast_timeout
    elif args.ufast == True:
        n_threads = ufast_threads
        timeout = ufast_timeout

if __name__ == "__main__":
    parse_args()
    cidr_to_list(cidr)
    
# use concurrent executor to speed up the execution 
    with concurrent.futures.ThreadPoolExecutor ( max_workers = n_threads ) as executor:
        task = {executor.submit(icmp_ping, I, timeout):I for I in ip_list}
        for future in concurrent.futures.as_completed(task):
            future.result()

    print ("Total up: {}\nTotal down: {}\nTotal unknown: {}".format(str(total_up), str(total_down), str(total_unknown)))
    
