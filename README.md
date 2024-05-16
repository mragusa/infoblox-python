# infoblox-python
infoblox scripts written in python utilizing infoblox-client

# Scripts
| Script Name | Purpose |
| :--- | :---: |
| infoblox-framework.py | Basic python framework to login to infoblox and use as a starting point for new scripts |
| ibxfileops.py | Perform basic fileops against Infoblox grid members/master |
| ibx-csvimport.py | Infoblox CSV import script utilizing infoblox-client module. |
| traffic-analysis.py | Read tcpdump PCAP file and display DNS queries that are higher that requested time delay. Default is 500ms | 
| dns-splitter.py | Read tcpdump pcap file and seperate specific dns transaction ID into a seperate file |
| dns-parser.py | Read PCAP file and display packets to the screen |

# Help Menus
## ibxfileops.py
```
% ./ibxfileops.py --help
usage: Infoblox FileOps Script [-h] [-u USER] [-p PASSWORD] [-m MEMBER] [-v]
                               [-c {NTP_KEY_FILE,DNS_CFG,DHCP_CFG,DHCPV6_CFG,RADIUS_CFG,DNS_CACHE,DNS_ACCEL_CACHE,DHCP_EXPERT_MODE_CFG,TRAFFIC_CAPTURE_FILE,DNS_STATS,DNS_RECURSING_CACHE}]
                               gmhostname

Provides functionality to perform getmemberops file operations on grid members

positional arguments:
  gmhostname            Grid Master IP

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -m MEMBER, --member MEMBER
  -v, --verbose         Enable Debug Mode
  -c {NTP_KEY_FILE,DNS_CFG,DHCP_CFG,DHCPV6_CFG,RADIUS_CFG,DNS_CACHE,DNS_ACCEL_CACHE,DHCP_EXPERT_MODE_CFG,TRAFFIC_CAPTURE_FILE,DNS_STATS,DNS_RECURSING_CACHE}, --config {NTP_KEY_FILE,DNS_CFG,DHCP_CFG,DHCPV6_CFG,RADIUS_CFG,DNS_CACHE,DNS_ACCEL_CACHE,DHCP_EXPERT_MODE_CFG,TRAFFIC_CAPTURE_FILE,DNS_STATS,DNS_RECURSING_CACHE}
                        Configuration file to download

Download member data from the appliance

```

> [!IMPORTANT]
> csvimports via api do not allow the - symbol in filenames. Concert all hyphens to dashes prior to import
> the filename specified on the CLI is only for naming the file in the GUI to better track what files are actively being imported by the CSV Task Manager

## ibx-csvimport.py
```
 % ./ibx-csvimport.py --help
usage: Infoblox CSV Custom Import [-h] [-u USER] [-p PASSWORD] [-v] [-f FILE] [-a {INSERT,UPDATE,REPLACE,DELETE,CUSTOM}] gmhostname

Use to import CSV for custom imports to grid master

positional arguments:
  gmhostname            Grid Master IP

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -v, --verbose         Enable Debug Mode
  -f FILE, --file FILE  CSV file for import
  -a {INSERT,UPDATE,REPLACE,DELETE,CUSTOM}, --action {INSERT,UPDATE,REPLACE,DELETE,CUSTOM}
                        CSV Import Action

Refer to documentation on custom csv import format
```

> [!NOTE]
> TODO
- [ ] Update script to allow full path to import file
- [ ] Convert hyphenes to dashes automatically in filename

> [!NOTE]
> if there are any errors during the csv import, they will automatically download to the current working directory

## traffic-analysis.py
```
 % ./traffic-analysis.py --help                                                                                
usage: traffic-analysis.py [-h] [-f FILE] [-s SOURCE] [-t TIME] [-o OUTPUT] [-v]

Script to parse traffic capture files for slow queries

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Traffic Capture File (default: None)
  -s SOURCE, --source SOURCE
                        DNS Server IP Address (default: None)
  -t TIME, --time TIME  Latency delay measured in seconds (default: 0.5)
  -r REPORT, --report REPORT
                        Query Traffic Report Count (default: query_traffic_count.txt)  
  -o OUTPUT, --output OUTPUT
                        Name of slow queries file output (default: slow_queries.txt)
  -v, --verbose         Verbose output (default: False)

This script will read a valid pcap file created by tcpdump and begin analysis to determine what DNS queries are slower that the provided timing (default 0.5 seconds aka 500ms. Upon
analysis, the output of all slow queries will be saved to a file in the following format query, query_id, latency. Wireshark can be used with the following filter: dns.id==<query_id> to
filter the existing packet capture file to only show the latent query in question. If a tcpdump file is too large and the desire is to break up the file into smaller segments for faster
processing, the following command can be used: tcpdump -r <packet_capture> -w <new_file> -C <size> example: tcpdump -r traffic.cap -w slow_queries -C 100. Processing ttime varies but a
100MB file takes about 10 mins

```
### Known Issues
> [!WARNING]
> traffic-analysis.py is single threaded and can take a long time to process very large pcap files. Current Processing time for a 1G PCAP is 5+ hours
> verbose output is overwhelimg. If needed, consider a redirect for the output to a file
> Converting larger pcap files to smaller ones for processing may be advisable. 95M pcap files take around 20 mins to process.

> [!NOTE]
> The script will generate two report files. The -r option will produce a report with query, count and the query IDs associated with these DNS queries.
> The -o option will produce a report with query, query id and latency. 

## dns-splitter.py
```
usage: dns-splitter.py [-h] -p PCAP -d DNSID

Parse pcap files and seperate specific DNS transaction IDs into new pcap file

options:
  -h, --help            show this help message and exit
  -p PCAP, --pcap PCAP  traffic capture file
  -d DNSID, --dnsid DNSID
                        dns query id

Uses transaction IDs found by traffic-analysis.py
```

## dns-parser.py
```
% ./dns-parser.py --help
usage: dns-parser.py [-h] -f FILE

Read a pcap file and display DNS packet fields.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the pcap file
```


[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
