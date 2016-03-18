#!/usr/bin/python

"""
(C) Copyright 2016 Holger Hans Peter Freyther

GNU AGPLv3+ 
"""

from scapy.all import rdpcap, Ether, IP, SCTP, SCTPChunkData, wrpcap
import sys

pcap = rdpcap(sys.argv[1])
pkts = []

i = 0
seq = 0
for pkt in pcap:
    ip = pkt['IP']
    layer = ip.payload
    while layer.name != 'NoPayload':
        if layer.name == 'SCTPChunkData':
            print("Pkt {} has data chunk".format(i))
            # re-create the chunkdata as I don't find the routine to just have this data...
            pkts.append(Ether()/IP()/SCTP(sport=2905,dport=2905,tag=0x84a5f973)/SCTPChunkData(reserved=0, delay_sack=0, unordered=0, beginning=1, ending=1, stream_id=0x1, proto_id=0x3, stream_seq=layer.stream_seq, tsn=layer.tsn, data=layer.data))
            seq = seq + 1
        layer = layer.payload
    i = i + 1

wrpcap('flattened.pcap', pkts)
