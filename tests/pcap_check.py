from scapy.all import rdpcap
import sys

in_file = sys.argv[1]
want_count = int(sys.argv[2])
pkts = 0

for pkt in rdpcap(in_file):
    pkts = pkts + 1

if want_count != pkts:
    sys.stderr.write("Wrong number of packets {} vs. {}\n".format(want_count, pkts))
    sys.exit(-1)

