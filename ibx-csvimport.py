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
parser.add_argument("-a", "--action", help="CSV Import Action", choices=['INSERT', 'UPDATE', 'REPLACE', 'DELETE', 'CUSTOM'], default="CUSTOM")
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
		reader = csv.reader(csvfile)
		for row in reader:
			if row:
				data.append(row)
	if args.verbose:
		print(data)
	return data

def prepare_files_dict(csv_data):
    files = {}
    all_rows_content = []

    for row in csv_data:
        # Process each value in the row to handle commas and special characters
        processed_row = []
        for value in row:
            # Enclose value in double quotes if it contains a comma or special characters
            if ',' in value or '\n' in value or '"' in value:
                processed_value = f'"{value}"'  # Enclose value in double quotes
            else:
                processed_value = value  # Use value as is
            processed_row.append(processed_value)
        
        # Join processed row values with commas to form a CSV row
        csv_row = ','.join(processed_row)
        all_rows_content.append(csv_row)

    # Join all CSV rows with newline characters to form the file content
    file_content = '\n'.join(all_rows_content)

    # Store the file content in the 'import_file' key of the files dictionary
    files["import_file"] = file_content

    return files



print("File: {}".format(args.file))
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
	if args.verbose:
		print(prepared_file)
	upload_status = conn.upload_file(file_upload["url"], prepared_file)
	if upload_status:
		print("File {} uploaded successfully {}".format(args.file, upload_status))
	else:
   		print("Error uploading file.")
	print("Starting Import")
	import_task = conn.call_func("csv_import", "fileop", {"action":"START", "on_error":"CONTINUE","operation":args.action, "separator":"COMMA", "token":file_upload["token"]})
	if import_task:
		print("Import Task: {}".format(import_task))
#		import_status = conn.get_object("csvimporttask", {"import_id":import_task["csv_import_task"]["import_id"]})
#		if import_status:
#			print(import_status)
	else:
		print("Error in import task")

else:
	print("Error uploading CSV file")
