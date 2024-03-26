#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse
import datetime

parser = argparse.ArgumentParser(
    prog="Infoblox FileOps Script",
    description="Provides functionality to perform getmemberops file operations on grid members",
    epilog="Download member data from the appliance",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-m", "--member")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable Debug Mode")
parser.add_argument("-c", "--config", help="Configuration file to download", choices=['NTP_KEY_FILE', 'DNS_CFG', 'DHCP_CFG', 'DHCPV6_CFG', 'RADIUS_CFG', 'DNS_CACHE', 'DNS_ACCEL_CACHE', 'DHCP_EXPERT_MODE_CFG', 'TRAFFIC_CAPTURE_FILE', 'DNS_STATS', 'DNS_RECURSING_CACHE'])
args = parser.parse_args()
# for debugging
if args.verbose:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
## Download DNS configuration file
if args.config:
	file = conn.call_func("getmemberdata", "fileop", {"member": args.member, "type": args.config})
	if file:
		print(file['url'])
		response = conn.download_file(file['url'])
		if response.status_code == 200:
			current_date = datetime.date.today()
			date = current_date.strftime("%Y-%m-%d")
			file_name = args.config + "_" + date + ".tar.gz"
			with open(file_name, 'wb') as f:
				f.write(response.content)
			print("File Downloaded")
		else:
			print("Error downloading file. Status code: " response.status_code)
