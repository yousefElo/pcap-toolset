## developped by Youssef ELOUAM
## date = 12.11.2020
## version 1.2

from scapy.all import rdpcap, Ether, IP, SCTP, SCTPChunkData, wrpcap
import sys
import os.path
import glob 
from time import time
from datetime import datetime
from argparse import ArgumentParser

def flatten_sctp_file(path):
    path = os.path.abspath(path)
    pcap = rdpcap(path)
    seq = 0
    print(str(datetime.now()) + "  : reading : " + path + " --> .... ")
    packets = []
    for pkt in pcap:
        ip = pkt['IP']
        ip_src=ip.src
        ip_dst=ip.dst
        layer = ip.payload
        time = pkt.time
        while layer.name != 'NoPayload':
            if layer.name == 'SCTP':
                sport = layer.sport
                dport = layer.dport
                tag = layer.tag
            if layer.name == 'SCTPChunkData':
                # re-create the chunkdata as I don't find the routine to just have this data...
                newPkt = Ether()/IP()/SCTP(sport=sport,dport=dport,tag=tag)/SCTPChunkData(reserved=0, delay_sack=0, unordered=0, beginning=1, ending=1, stream_id=layer.stream_id, proto_id=layer.proto_id, stream_seq=layer.stream_seq, tsn=layer.tsn, data=layer.data)
                newPkt.time = time
                newPkt['IP'].src = ip_src
                newPkt['IP'].dst = ip_dst
                packets.append(newPkt)
                seq = seq + 1
            layer = layer.payload
    
    folderName = os.path.dirname(os.path.abspath(path))
    fileName = os.path.basename(os.path.abspath(path))
    
    try:
        os.makedirs(folderName + "\\_processed")
        print("new folder was created : " + folderName + "\\_processed")
    except FileExistsError:
        print(path + "\\_processed : this folder exist already")
        pass

    wrpcap(folderName + "\\_processed\\" + fileName, packets)
    print(str(datetime.now()) + "  : file name : " + fileName + " --> DONE")
    print("all result file was generated under the path : " + folderName + "\\_processed\\")

def flatten_sctp_folder(path):

    folderName = os.path.abspath(path)
    
    try:
        os.makedirs(folderName + "\\_processed")
        print("new folder was created : " + folderName + "\\_processed")
    except FileExistsError:
        print(folderName + "\\_processed : this folder exist already")
        pass

    allFiles = glob.glob(folderName + '/*.pcap')
    packets = []
    file_count = 0
    for file in allFiles :
        file_name = os.path.basename(file)
        file_count += 1
        print(str(datetime.now()) + "  : reading : " + file_name + " --> .... " + str(file_count))
        pcap = rdpcap(file)
        seq = 0
        for pkt in pcap:
            ip = pkt['IP']
            layer = ip.payload
            time = pkt.time
            while layer.name != 'NoPayload':
                if layer.name == 'SCTP':
                    sport = layer.sport
                    dport = layer.dport
                    tag = layer.tag
                if layer.name == 'SCTPChunkData':
                    # re-create the chunkdata as I don't find the routine to just have this data...
                    newPkt = Ether()/IP()/SCTP(sport=sport,dport=dport,tag=tag)/SCTPChunkData(reserved=0, delay_sack=0, unordered=0, beginning=1, ending=1, stream_id=layer.stream_id, proto_id=layer.proto_id, stream_seq=layer.stream_seq, tsn=layer.tsn, data=layer.data)
                    newPkt.time = time
                    packets.append(newPkt)
                    seq = seq + 1
                layer = layer.payload
        wrpcap(folderName + "\\_processed\\" + file_name, packets)
        print(str(datetime.now()) + "  : file name : " + file_name + " --> DONE")
        packets = []
    print("count of processed file : " + str(file_count))
    print("all result file was generated under the path : " + folderName + "\\_processed\\")

    #extension = os.path.splitext(file_name)[1]
    #path = os.path.splitext(file_name)[-1]
    #wrpcap(str(int(time())) + '_merged_file.pcap', packets)
    #print("\n")
    #print(str(datetime.now()) + "  : your files was processed successfuly, new file generated : {}".format(str(int(time())) + '_merged_file.pcap'))

if __name__ == '__main__':
    
    #inp_path = sys.argv[1]
    #flatten_sctp(inp_path)
    #sys.exit(0)
    
    parser = ArgumentParser()
    parser.add_argument("-file", dest="filePath",
                    default="", action="store",
                    help="\t Specify file Path")

    parser.add_argument("-folder", dest="folderPath",
                    default="", action="store",
                    help="\t Specify folder Path")

    args = parser.parse_args()

    filePath = os.path.abspath(args.filePath)
    folderPath = os.path.abspath(args.folderPath)

    if folderPath[-1] == "\"":
        folderPath = folderPath[:-1]

    if os.path.isfile(filePath) :
        flatten_sctp_file(filePath)
        sys.exit(0)
    elif os.path.isdir(folderPath) :
        flatten_sctp_folder(folderPath)
        sys.exit(0)
    else : 
        print("not valid folder path or file path") 
        sys.exit(0)