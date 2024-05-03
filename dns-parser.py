#!/usr/bin/env python3

import argparse
from scapy.all import *

def process_dns_packet(packet):
    if packet.haslayer(DNS):
        dns = packet[DNS]
        print("Transaction ID:", dns.id)
        print("QR (Query/Response):", "Response" if dns.qr else "Query")
        print("Opcode:", dns.opcode)
        print("AA (Authoritative Answer):", dns.aa)
        print("TC (Truncated):", dns.tc)
        print("RD (Recursion Desired):", dns.rd)
        print("RA (Recursion Available):", dns.ra)
        print("Z (Reserved):", dns.z)
        print("RCODE (Response Code):", dns.rcode)
        print("QDCOUNT (Number of questions):", dns.qdcount)
        print("ANCOUNT (Number of answers):", dns.ancount)
        print("NSCOUNT (Number of authority records):", dns.nscount)
        print("ARCOUNT (Number of additional records):", dns.arcount)
        print("Questions:")
        for q in dns.qd:
            print("\tName:", q.qname)
            print("\tType:", q.qtype)
            print("\tClass:", q.qclass)
        if dns.ancount:
            print("Answers:")
            for a in dns.an:
                print("\tName:", a.rrname)
                print("\tType:", a.type)
                print("\tTTL:", a.ttl)
                if hasattr(a, "rdata"):  # Check if rdata field exists
                    print("\tData:", a.rdata)
        if dns.nscount:
            print("Authority Records:")
            for auth in dns.ns:
                print("\tName:", auth.rrname)
                print("\tType:", auth.type)
                print("\tTTL:", auth.ttl)
                if hasattr(auth, "rdata"):  # Check if rdata field exists
                    print("\tData:", auth.rdata)
        if dns.arcount:
            print("Additional Records:")
            for additional in dns.ar:
                print("\tName:", additional.rrname)
                print("\tType:", additional.type)
                print("\tTTL:", additional.ttl)
                if hasattr(additional, "rdata"):  # Check if rdata field exists
                    print("\tData:", additional.rdata)
        print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description='Parse DNS packets in a pcap file')
    parser.add_argument('-f', '--file', dest='pcap_file', required=True, help='Path to the pcap file')
    args = parser.parse_args()

    packets = rdpcap(args.pcap_file)

    for packet in packets:
        process_dns_packet(packet)

if __name__ == "__main__":
    main()
