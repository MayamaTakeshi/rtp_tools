#!/usr/bin/python3

from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import udp
from pypacker.layer567 import rtp

import sys

def usage(app):
    print("""
Usage: %(app)s pcap_file src_ip src_port dst_ip dst_port
Ex:    %(app)s test.pcap 192.168.1.1 10000 192.168.1.2 20000
""" % {"app": app})

if len(sys.argv) != 6:
    usage(sys.argv[0])
    sys.exit(1)

app, pcap_file, src_ip, src_port, dst_ip, dst_port = sys.argv
src_port = int(src_port)
dst_port = int(dst_port)

#print(pcap_file)

preader = ppcap.Reader(filename=pcap_file)

for ts, buf in preader:
    eth = ethernet.Ethernet(buf)

    if eth[ethernet.Ethernet, ip.IP, udp.UDP] is not None:
        if eth[ip.IP].src_s == src_ip and eth[udp.UDP].sport == src_port and eth[ip.IP].dst_s == dst_ip and eth[udp.UDP].dport == dst_port:
            r = rtp.RTP(eth[udp.UDP].body_bytes)
            print("%d: pt=%s ts=%s seqnum=%s" % (
                ts, 
                r.pt,
                r.ts,
                r.seq
            ))
            sys.stdout.write("payload: ")
            for b in r.body_bytes:
                sys.stdout.write(hex(b) + " ")
            print("")

