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

opts = {
    "host": args.gmhostname,
    "username": args.user,
    "password": args.password,
    "max_results": 20000,
    "http_request_timeout": 10,
    "http_pool_connections": 10,
    "http_pool_maxsize": 10,
    "paging": False,
}
conn = connector.Connector(opts)
# get all auth zones
zone_auth = conn.get_object("zone_auth", {"fqdn~": ".*"})
# print auth zones
zone_auth = conn.get_object("zone_auth", {"fqdn~": ".*"})
zone_forward = conn.get_object("zone_forward", {"fqdn~": ".*"})
zone_delegated = conn.get_object("zone_delegated", {"fqdn~": ".*"})
zone_stub = conn.get_object("zone_stub", {"fqdn~": ".*"})
print(zone_auth)
print(zone_forward)
print(zone_delegated)
print(zone_stub)
