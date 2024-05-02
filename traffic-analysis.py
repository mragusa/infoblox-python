#!/usr/bin/env python3

from scapy.all import *
from tqdm import tqdm

# import multiprocessing
import argparse
import statistics


class DnsAnalyzer:
    def __init__(self, capture_file, source_ip, time_delay, output_file, verbose=False):
        self.capture_file = capture_file
        self.source_ip = source_ip.strip()
        self.time_delay = time_delay
        self.verbose = verbose
        self.queries_received = []
        self.responses_sent = []
        self.file = output_file

    def process_packet(self, packet):
        if self.verbose:
            print(packet)
        if DNS in packet and (
            packet[IP].dst == self.source_ip or packet[IP].src == self.source_ip
        ):
            dns = packet.getlayer(DNS)
            if self.verbose:
                print(dns)  # Corrected indentation
            if dns is not None:
                if DNSQR in dns:
                    if packet[IP].dst == self.source_ip:
                        self.queries_received.append(
                            {
                                "query_id": dns.id,
                                "query_request": dns.qd.qname,
                                "query_time": packet.time,
                            }
                        )
                    if packet[IP].src == self.source_ip:
                        if isinstance(dns.an, DNSRR):
                            response_name = dns.an.rrname
                            self.responses_sent.append(
                                {
                                    "query_id": dns.id,
                                    "response_time": packet.time,
                                    "rrname": response_name,
                                }
                            )
                            if self.verbose:
                                print(
                                    "{}{}{}".format(dns.id, dns.qd.qname, packet.time)
                                )
                        elif isinstance(dns.an, list):
                            for response in dns.an:
                                response_name = response.rrname
                                self.responses_sent.append(
                                    {
                                        "query_id": dns.id,
                                        "response_time": packet.time,
                                        "rrname": response_name,
                                    }
                                )
                                if self.verbose:
                                    print(
                                        "{}{}{}".format(
                                            dns.id, packet.time, response_name
                                        )
                                    )

    def analyze(self):
        total_packets = 0
        with PcapReader(self.capture_file) as packets:
            for _ in packets:
                total_packets += 1

        print("\033[94mTotal packets found {} in {}\033[0m".format(total_packets, self.capture_file))
        print()
        # Add the tqdm progress bar to the loop
        with tqdm(
            total=total_packets, desc="Processing packets", unit="packets", colour="blue"
        ) as pbar:
            with PcapReader(self.capture_file) as packets:
                for packet in packets:
                    self.process_packet(packet)
                    pbar.update(1)  # Update the progress bar

        print()
        print("\033[94mNumber of queries received: {}\033[0m".format(len(self.queries_received)))
        print("\033[94mNumber of responses sent: {}\033[0m".format(len(self.responses_sent)))
        print()
        latency_times = []
        slow_queries = []
        with tqdm(
            total=len(self.queries_received),
            desc="Processing Query Latency",
            unit="queries",
            colour="green",
        ) as pbar:
            for query in self.queries_received:
                query_id = query["query_id"]
                query_match = next(
                    (
                        resp
                        for resp in self.responses_sent
                        if resp["query_id"] == query_id
                    ),
                    None,
                )
                if query_match:
                    latency_time = query_match["response_time"] - query["query_time"]
                    if self.verbose:
                        print(
                            "Query ID: {}, Latency Time: {}".format(
                                query_id, latency_time
                            )
                        )
                    latency_times.append(latency_time)
                    pbar.update(1)
                    if latency_time > self.time_delay:
                        slow_queries.append(
                            {
                                "query": query["query_request"],
                                "query_id": query_id,
                                "latency": latency_time,
                            }
                        )
        print()
        print("\033[94mTotal Slow Queries\033[0m: \033[93m{}\033[0m".format(len(slow_queries)))
        print("\033[92m`Saving slow queries to file\033[0m")
        print()
        with open(self.file, "w") as f:
            for query in slow_queries:
                f.write(str(query) + "\n")
        print()
        print("\033[95mProcessing Latency Times\033[0m")
        print()
        if latency_times:
            lowest_latency = min(latency_times)
            highest_latency = max(latency_times)
            median_latency = statistics.median(latency_times)

            print("\033[94mLowest Latency: {}\033[0m".format(lowest_latency))
            print("\033[91mHighest Latency: {}\033[0m".format(highest_latency))
            print("\033[93mMedian Latency: {}\033[0m".format(median_latency))

        total = total_packets
        slow = len(slow_queries)
        percentage_difference = ((total - slow) / total) * 100
        print()
        print("\033[94mTotal Packets: {}\033[0m".format(total))
        print("\033[91mSlow Queries: {}\033[0m".format(slow))
        print("\033[94mPercentage Difference: {}%\033[0m".format(percentage_difference))


def main():
    parser = argparse.ArgumentParser(
        description="Script to parse traffic capture files for slow queries",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="This script will read a valid pcap file created by tcpdump and begin analysis to determine what DNS queries are slower that the provided timing (default 0.5 seconds aka 500ms. Upon analysis, the output of all slow queries will be saved to a file in the following format query, query_id, latency. Wireshark can be used with the following filter: dns.id==<query_id> to filter the existing packet capture file to only show the latent query in question. If a tcpdump file is too large and the desire is to break up the file into smaller segments for faster processing, the following command can be used: tcpdump -r <packet_capture> -w <new_file> -C <size> example: tcpdump -r traffic.cap -w slow_queries -C 100. Processing ttime varies but a 100MB file takes about 10 mins",
    )
    parser.add_argument("-f", "--file", help="Traffic Capture File")
    parser.add_argument("-s", "--source", help="DNS Server IP Address")
    parser.add_argument(
        "-t", "--time", help="Latency delay measured in seconds", default=0.5
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Name of slow queries file output",
        default="slow_queries.txt",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    analyzer = DnsAnalyzer(
        args.file, args.source, float(args.time), args.output, args.verbose
    )
    analyzer.analyze()


if __name__ == "__main__":
    main()
