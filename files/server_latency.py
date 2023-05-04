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

class Tree:
    def __init__(self, ip):
        self.children = []
        self.data = ip

T = Tree("server")
D = {}
count = 0
iface = None
my_data = ""

def ip_to_int(list):
    return (list[0] * 256**3) + (list[1] * 256**2) + (list[2] * 256) + (list[3])

def extract_path(list):
    path = []
    start = 34
    path.append(ip_to_int(list[start:start + 4]))
    while list[start + 4] == 18 and list[start + 5] == 18:
        start += 6
        path.append(ip_to_int(list[start:start + 4]))
    path.reverse()
    return path

def add_children(ips, parent, D):
    if len(ips) == 0: return
    path = []
    for ip in ips:
        new_node = Tree(ip)
        D[ip] = new_node
        path.append(new_node)
    for i in range(1, len(path)):
        path[i].children.append(path[i-1])
    parent.children.append(path[-1])


def add_path_to_tree(path, T, D):
    for index, ip in enumerate(path):
        if ip in D:
            add_children(path[:index], D[ip], D)
            return
    add_children(path, T, D)

def print_tree(node, depth):
    s = "\t" * depth + str(node.data)
    print(s)
    for c in node.children:
        print_tree(c, depth+1)

def tree_to_bytes(T):
    pkt = []
    Q = []
    Q.append(T)
    #bfs
    while Q:
        parent = Q.pop(0)
        ip = parent.data
        if(ip == "server"):
            for node in parent.children:
                Q.append(node)
            continue
        else:
            for node in parent.children:
                Q.append(node)
                pkt = pkt + (list(ip.to_bytes(4, 'big'))) # 'host' node
                pkt = pkt + (list(node.data.to_bytes(4, 'big'))) # receiving node
                pkt = pkt + [50, 50]
    if pkt:
        pkt[-1] = 0
        pkt[-2] = 0
    pkt = list(map(lambda x: chr(x), pkt))
    return ''.join(pkt)

def build_tree(pkt):
    global T
    global D
    global count
    byteList = list(bytes(pkt))
    if (count == 2 and byteList[12] == 18):
        send_phase(T, D);
    elif(byteList[12] == 18 and byteList[13] == 18):
        path = extract_path(byteList)
        add_path_to_tree(path, T, D)
        print_tree(T, 0)
        count += 1

def send_phase(T, D):
    global iface
    global my_data
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type = 0x3232)
    tree_data = tree_to_bytes(T)
    pkt = pkt / tree_data
    pkt = pkt / my_data
    print(list(bytes(pkt)))
    sendp(pkt, iface=iface, verbose=False)


def main():
    global iface
    global my_data
    my_data = sys.argv[1]
    for i in get_if_list():
        if "ens7" in i:
            iface=i
            break;
    print ("Waiting for connections on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: build_tree(x))

if __name__ == '__main__':
    main()
