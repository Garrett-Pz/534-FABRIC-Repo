#!/usr/bin/env python3
#GARRETT PARZYCH
import os
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR


def handle_pkt(pkt):
    byteList = list(bytes(pkt))
    if(byteList[12] == 50 and byteList[13] == 50):
        print("got EMISSION packet:")
        pkt.show2()
        print(byteList)
        sys.stdout.flush()
    if(byteList[12] == 80 and byteList[13] == 80):
        print("got EMISSION packet:")
        pkt.show2()
        print(byteList)
        sys.stdout.flush()
    if(byteList[12] == 81 and byteList[13] == 81):
        print("got EMISSION packet:")
        pkt.show2()
        print(byteList)
        sys.stdout.flush()
    elif(byteList[12] == 18 and byteList[13] == 18):
        print("got CONNECTION packet:")
        print(byteList)
        sys.stdout.flush()


def main():
    iface = None
    for i in get_if_list():
        if "ens7" in i:
            iface=i
            break;
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
