#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox FileOps Script",
    description="Provides functionality to perform getmemberops file operations on grid members",
    epilog="Download DNS/DHCP configuration, support bundles",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true", help="Enable Debug Mode")
parser.add_argument("-b", "--bind", action="store_true", help="Download BIND configuration")
parser.add_argument("-m", "--member")
args = parser.parse_args()
# for debugging
if args.debug:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
# Download DNS configuration file
if args.bind:
	file = conn.call_func("getmemberdata", "fileop", {"member": member, "type": "DNS_CFG"})
	conn.file_download(file['url'])
