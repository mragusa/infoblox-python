#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox Zone Information",
    description="Displays DNS zones and nsgroups/members assigned to them",
    epilog="Zones without an NS group are flagged for review",
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
zone_auth = conn.get_object(
    "zone_auth",
    return_fields=["fqdn", "ns_group", "external_primaries", "external_secondaries"],
)
zone_forward = conn.get_object(
    "zone_forward",
    return_fields=["fqdn", "ns_group", "forward_to", "forwarding_servers"],
)
zone_delegated = conn.get_object(
    "zone_delegated", return_fields=["fqdn", "ns_group", "delegate_to"]
)
zone_stub = conn.get_object(
    "zone_stub",
    return_fields=[
        "fqdn",
        "ns_group",
        "external_ns_group",
        "stub_members",
        "stub_from",
    ],
)


# print auth zones
print("\033[93mAuth Zones\033[0m {}".format(len(zone_auth)))
if zone_auth:
    # print(zone_auth)
    for za in zone_auth:
        if "ns_group" in za:
            print("NS Group: {} {}".format(za["fqdn"], za["ns_group"]))
        elif "external_primaries" in za:
            print(
                "Investigate: {} {} {}".format(
                    za["fqdn"], za["external_primaries"], za["external_secondaries"]
                )
            )
        else:
            print("Investigate: {}".format(za["fqdn"]))
print("\033[93mForward Zones\033[0m {}".format(len(zone_forward)))
if zone_forward:
    for zf in zone_forward:
        if zf["ns_group"]:
            print("NS Group: {} {}".format(zf["fqdn"], zf["ns_group"]))
        if zf["forward_to"]:
            print(
                "Investigate: {} {}".format(zf["forward_to"], zf["forwarding_servers"])
            )
print("\033[93mDelegated Zones\033[0m {}".format(len(zone_delegated)))
if zone_delegated:
    for zd in zone_delegated:
        if "ns_group" in zd:
            print("NS Group: {} {}".format(zd["fqdn"], zd["ns_group"]))
        elif "delegate_to" in zd:
            print("Investigate: {} {}".format(zd["fqdn"], zd["delegate_to"]))
        else:
            print("Investigate: {}".format(za["fqdn"]))

print("\033[93mStub Zones\033[0m {}".format(len(zone_stub)))
if zone_stub:
    for zs in zone_stub:
        if "ns_group" in zs:
            print("NS Group: {} {}".format(zs["fqdn"], zs["ns_group"]))
        elif "external_ns_group" in zs:
            print("NS Group: {} {}".format(zs["fqdn"], zs["external_ns_group"]))
        elif "stub_from" in zs:
            print(
                "Investigate: {} {} {}".format(
                    zs["fqdn"], zs["stub_members"], zs["stub_from"]
                )
            )
        else:
            print("Investigate: {}".format(zs["fqdn"]))
