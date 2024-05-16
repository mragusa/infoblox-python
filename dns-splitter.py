#!/usr/bin/env python3

from scapy.all import *
import click

@click.command()
@click.option("-p", "--pcap", help="path to PCAP file")
@click.option("-i", "--id", help="DNS ID to filter on")

def write:
    wrpcap(id + '.pcap', pkt, append=True)  #appends packet to output file

def splitpcap(pcap):
    pckts = rdpcap(pcap)
    for p in pckts:
        if p.haslayer(DNS):
            if p.dns.id == id:
                write(p)

if __name__ == '__main__':
    def splitpcap()
