#!/usr/bin/env python3

from scapy.all import *
from tqdm import tqdm
#import multiprocessing
import argparse

class DnsAnalyzer:
    def __init__(self, capture_file, source_ip, time_delay, verbose=False):
        self.capture_file = capture_file
        self.source_ip = source_ip.strip()
        self.time_delay = time_delay
        self.verbose = verbose
        self.queries_received = []
        self.responses_sent = []
        self.slow_latency = []

    def process_packet(self, packet):
        if DNS in packet and (packet[IP].dst == self.source_ip or packet[IP].src == self.source_ip):
            dns = packet[DNS]
            print(dns)  # Corrected indentation
            if DNSQR in dns:
                if packet[IP].dst == self.source_ip:
                    self.queries_received.append({"query_id": dns.id, "query_request": dns.qd.qname, "query_time": packet.time})
                    print("{}{}{}".format(dns.id, dns.qd.qname, packet.time))
                if packet[IP].src == self.source_ip:
                    for x in range(dns.ancount):
                        response_name = dns.an[x].rrname
                        self.responses_sent.append({"query_id": dns.id, "response_time": packet.time, "rrname": response_name})
                        print("{}{}{}".format(dns.id, packet.time, response_name))


    def analyze(self):
        packets = PcapReader(self.capture_file)
        total_packets = sum(1 for _ in packets)
        print("Total packets found {} in {}".format(total_packets, self.capture_file))

        for packet in tqdm(packets, desc="Processing packets", unit="packets"):
            self.process_packet(packet)

        print("Queries received:", len(self.queries_received))
        print("Responses sent:", len(self.responses_sent))

        with tqdm(total=len(self.queries_received), desc="Processing queries", unit="queries") as pbar:
            latency_times = []
            for query in self.queries_received:
                query_id = query["query_id"]
                query_match = next(
                    (resp for resp in self.responses_sent if resp["query_id"] == query_id),
                    None,
                )   
                if query_match:
                    latency_time = query_match["response_time"] - query["query_time"]
                    if self.verbose:
                        print(
                            "Query ID: {}, Latency Time: {}, Query: {}".format(
                                query_id, latency_time, query["query_request"]
                            )   
                        )   
                    latency_times.append(latency_time)
                    pbar.update(1)
                    if latency_time > self.time_delay:
                        self.slow_latency.append(
                            {   
                                "query": query["query_request"],
                                "query_id": query_id,
                                "latency": latency_time,
                            }   
                        )

def main():
    parser = argparse.ArgumentParser(
        description="Script to parse traffic capture files for slow queries",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-f", "--file", help="Traffic Capture File")
    parser.add_argument("-s", "--source", help="Source IP address of the DNS server")
    parser.add_argument("-t", "--time", help="Latency delay measured in seconds", default=0.5)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    analyzer = DnsAnalyzer(args.file, args.source, float(args.time), args.verbose)
    analyzer.analyze()

if __name__ == "__main__":
    main()
