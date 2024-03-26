#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox CSV Custom Import",
    description="Use to import CSV for custom imports to grid master",
    epilog="Refer to documentation on custom csv import format",
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

file_upload = conn.call_func("uploadinit", "fileop", {"file": args.file })  
if file_upload:
	print("File Token: {}".format(file_upload["token"]))
	import_task = conn.call_func("csv_import", "fileop", {"action": "START", "on_error": "CONTINUE","operation": "CUSTOM", "seperator": "commona", "token": file_upload["token"]})
	if import_task:
		print(csv_import_task)
	else:
		print("Error in import task")
else:
	print("Error uploading CSV file")
