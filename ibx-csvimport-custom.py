#!/usr/bin/python3

import urllib3
from urllib3.filepost import encode_multipart_formdata
from urllib3.util import make_headers
from urllib3.fields import RequestField
from urllib.parse import urlparse
urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects

import csv
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
parser.add_argument("-f", "--file", help="CSV file for import")	
args = parser.parse_args()
# for debugging
if args.verbose:
    import logging
    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
http = urllib3.PoolManager(cert_reqs='CERT_NONE', ca_certs=False)

def read_csv_file(csv_file_path):
	data = []
	with open(csv_file_path, newline='') as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
			data.append(row)
	return data

def prepare_files_dict(csv_data):
	files = {}
	for i, row in enumerate(csv_data):
		files[f'file_{i}'] = (
			f'network_upload_{i}.csv',
			'\n'.join(f"{row['header-network']},{row['import-action']},{row['address*']},{row['netmask*']},{row['network_view']}" for row in csv_data),
			'text/csv'
	)
	return files

print("File: {}".format(args.file))
#file_upload = conn.call_func("uploadinit", "fileop", {"filename": args.file })  
file_upload = conn.call_func("uploadinit", "fileop", {})
if file_upload:
	print("File Token: {} File URL: {}".format(file_upload["token"], file_upload["url"]))
	parsed_url = urlparse(file_upload["url"])
	url_path = parsed_url.path
	print(url_path)
	print("Preparing File: {}".format(args.file))
	csv_import_data = read_csv_file(args.file)
	prepared_file = prepare_files_dict(csv_import_data)
	print("Uploading File")
	upload_status = conn.upload_file(file_upload["url"], prepared_file)
	if upload_status:
		print("File uploaded successfully {}".format(upload_status))
		uploaded_file = conn.call_func("setfiledest", "fileop", {"dest_path": "import_file", "token": file_upload["token"]})
		print("Starting Import")
		import_task = conn.call_func("csv_import", "fileop", {"action": "START", "on_error": "CONTINUE","operation": "CUSTOM", "separator": "COMMA", "token": file_upload["token"]})
		if import_task:
			print(import_task)
		else:
			print("Error in import task")
	else:
    		print(f"Error uploading file. Status code: {response.status}")

else:
	print("Error uploading CSV file")
