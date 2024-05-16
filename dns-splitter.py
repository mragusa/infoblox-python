#!/usr/bin/env python3

from scapy.all import *
import argparse 

def write(pkt, dnsid):
    wrpcap(dnsid + '.pcap', pkt, append=True)  #appends packet to output file

def splitpcap(pcap, dnsid):
    print("Opening file: {}".format(pcap))
    print("Searching for Query ID: {}".format(dnsid))
    pckts = rdpcap(pcap)
    for p in pckts:
        if DNS in p:
            #print("DNS packet found")
            dns = p.getlayer(DNS)
            if dns is not None:
                #print(type(dns.id))
                if dns.id == int(dnsid):
                    print("Match found for {}".format(dns.id))
                    write(p, dnsid)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", help="traffic capture file")
    parser.add_argument("-d", "--dnsid", help="dns query id")
    args = parser.parse_args()

    splitpcap(args.pcap, args.dnsid)

if __name__ == '__main__':
    main()
