#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox Script Framework",
    description="Provides basic python script framework",
    epilog="Edit as needed",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable Debug Mode")
args = parser.parse_args()
# for debugging
if args.verbose:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
# get all network_views
network_views = conn.get_object("networkview")
# print network view
print(network_views)
