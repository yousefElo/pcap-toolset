from scapy.all import rdpcap, Ether, IP, SCTP, SCTPChunkData, wrpcap
import sys
import os.path

def flatten_sctp(file_name):
    pcap = rdpcap(file_name)
    packets = []

    i = 0
    seq = 0

    for pkt in pcap:
        ip = pkt['IP']
        layer = ip.payload
        while layer.name != 'NoPayload':
            if layer.name == 'SCTP':
                sport = layer.sport
                dport = layer.dport
                tag = layer.tag
            if layer.name == 'SCTPChunkData':
                # re-create the chunkdata as I don't find the routine to just have this data...
                packets.append(Ether()/IP()/SCTP(sport=sport,dport=dport,tag=tag)/SCTPChunkData(reserved=0, delay_sack=0, unordered=0, beginning=1, ending=1, stream_id=layer.stream_id, proto_id=layer.proto_id, stream_seq=layer.stream_seq, tsn=layer.tsn, data=layer.data))
                seq = seq + 1
            layer = layer.payload
        i = i + 1
    
    extension = os.path.splitext(file_name)[1]
    file_name = os.path.splitext(file_name)[0]
    
    wrpcap(file_name + '_out'+ extension, packets)
    print("your file was processed successfuly, new file generated under {}_out{}".format(file_name, extension))

if __name__ == '__main__':
    inp_fn = sys.argv[1]
    flatten_sctp(inp_fn)
    sys.exit(0)


