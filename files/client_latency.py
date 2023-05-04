#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import AsyncSniffer, sniff, sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

t1 = 0

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "ens7" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def stop(pkt):
    time.sleep(0.5)
    return True

def handle_pkt(t0, t1):
    print("got pkt")
    print(t1 - t0)


def main():
    if len(sys.argv)<3:
        print('pass arguments: <destination> <num_packets>')
        exit(1)
    addr = socket.gethostbyname(sys.argv[1])
    num = int(sys.argv[2])
    iface = get_if()

    #print("beginning test on interface %s to %s" % (iface, str(addr)))
    #t0 = time.perf_counter()
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / IP(dst=addr)
    for i in range(num):
        print(time.time())
        sendp(pkt, verbose = False)
    #sniff(prn = lambda x: handle_pkt())








if __name__ == '__main__':
    main()
