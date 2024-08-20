#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox Network/Range Updater",
    description="Update network and range with a new member and unassign FOA",
    epilog="Often during hardware or datacenter migrations, it becomes nessasary to move dhcp networks between members. This script will allow an administrator to update the network assignment for a partciular network and then update the dhcp range to that particular member and unassign the FoA",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable Debug Mode")
parser.add_argument("-n", "--network", help="network to update")
parser.add_argument("-m", "--member", help="new member to assign to network")
args = parser.parse_args()
# for debugging
if args.verbose:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
# get network
# 1. Retrieve network, range, member
# 2. Update network member assignment (append to list do not remove)
# 3. Update dhcp range with new member
# Retreive network range
network = conn.get_object(
    "network", {"network~": args.network}, return_fields=["members"]
)
# Retreive dhcp range
ipv4range = conn.get_object("range", {"network": args.network})
# Retreive grid member
member = conn.get_object(
    "member", {"host_name~": args.member}, return_fields=["host_name", "vip_setting"]
)
if args.verbose:
    print("Range: {}".format(ipv4range))
    print("Network: {}".format(network))
    print("Member: {}".format(member))
for n in network:
    if args.verbose:
        print("Network Reference: {}".format(n["_ref"]))
    if member:
        # Check if member is already assigned to network
        if not any(n["members"][0]["name"] == args.member for d in n["members"]):
            print("Member already assigned to network")
        else:
            # Delete ipv6addr keys to avoid errors on network update
            for m in n["members"]:
                del m["ipv6addr"]
            if args.verbose:
                print("Member: {}".format(member))
            # Append new dhcp member struct to network range
            n["members"].append(
                {
                    "name": member[0]["host_name"],
                    "ipv4addr": member[0]["vip_setting"]["address"],
                    "_struct": "dhcpmember",
                }
            )
            if args.verbose:
                print("New Members: {}".format(n["members"]))
            # Update network with new member
            update_network = conn.update_object(n["_ref"], {"members": n["members"]})
            if update_network:
                print("Network range updated Successful")
            else:
                print("DHCP range update Failed")
    else:
        print("Grid member not found")
for r in ipv4range:
    # Update DHCP range to use a grid member instead of FOA
    update_range = conn.update_object(
        r["_ref"],
        {
            "member": {
                "name": member[0]["host_name"],
                "ipv4addr": member[0]["vip_setting"]["address"],
                "_struct": "dhcpmember",
            }
        },
    )
    if update_range:
        print("DHCP range updated successfully")
    else:
        print("DHCP range update failed")
