#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox Range Information",
    description=" Displays NIOS DHCP Range member/FOA assignment",
    epilog=" Networks without member or HOA assignments will have the tag Invetigate in front of them",
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
# get all range
dhcp_ranges = conn.get_object(
    "range",
    {"network~": ".*"},
    return_fields=["failover_association", "network", "member"],
)
# print range
if dhcp_ranges:
    for dr in dhcp_ranges:
        # print(dr)
        # if dr["failover_association"]:
        if "failover_association" in dr:
            print(
                "FOA Assigned: {} {}".format(dr["network"], dr["failover_association"])
            )
        elif "member" in dr:
            print("Investigate: {} {}".format(dr["network"], dr["member"]))
        else:
            print("Investigate: {}".format(dr["network"]))
