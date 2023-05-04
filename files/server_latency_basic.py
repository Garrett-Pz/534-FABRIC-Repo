#!/usr/bin/env python3
#GARRETT PARZYCH
import os
import sys
import struct

from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

iface = None
small_data = "shortdatablockshortdatablockshortdatablockshortdatablockshortdatablockshortdatablockshortdatablo"
large_data = "largerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablocklargerdatablockla"
very_large_data = "muchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargemuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlargerdatablockmuchlarg"


for i in get_if_list():
        if "ens7" in i:
            iface=i
            break;
            
def handle_pkt(pkt):
    if IP in pkt and pkt[IP].dst == '10.0.1.1':
        #print("recv packet from ", pkt[IP].src)
        new_pkt = Ether() / IP(src=pkt[IP].dst, dst=pkt[IP].src) / small_data
        sendp(new_pkt, iface = iface, verbose = False)
    
            
sniff(iface = iface, prn = lambda x: handle_pkt(x))
