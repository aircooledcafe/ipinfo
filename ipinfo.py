#!/usr/bin/env python3

import requests
import json
import argparse
import urllib3
import os
from dotenv import load_dotenv

# Supress SSL warning when using verify=False to get arounod Zscaler certificate issues
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Obtain details about a give IP address or list of IP addresses")
parser.add_argument("-i", "--ipaddress", type=str, help="The IP address you want to query excluding")
parser.add_argument("-l", "--list", help="A file with a list of IP address, one per line")
parser.add_argument("-f", "--file", help="Optional: Output ASNs to a file, will be a text named after the ASN", action="store_true")
args = parser.parse_args()

load_dotenv()

mal_ip="144.31.221.84"

ip_api_key = os.getenv('IPINFO_API_KEY')
vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
#print(ip_api_key)
#print(vt_api_key)
ipinfo_base_url = "https://api.ipinfo.io/lite/"
vt_base_urel = "https://www.virustotal.com/api/v3/ip_addresses/"

ip = args.ipaddress
ip_list = args.list
output_file = args.file

# Get IP detail from IPInfo
def get_ip_info(ip):
    query_url = f"{ipinfo_base_url}{ip}?token={ip_api_key}"
    res = requests.get(query_url, verify=False)
    data = res.json()
    return data

# Get IP detail from Virus Total
def get_ip_info(ip):
    headers = {'x-apikey': vt_api_key,
            'accept': 'application/json'}
    query_url = f"{vt_base_url}{ip}"
    res = requests.get(query_url, ,headers=headers, verify=False)
    data = res.json()
    return data

# Print IP infor to console:
def print_ip_details(json_data):
    data = json_data
    print(data)
    ip = data["ip"]
    asn = data["asn"]
    aso = data["as_name"]
    as_domain = data["as_domain"]
    as_country = data["country"]
    as_country_code = data["country_code"]
    print(f"{ip:<20}{asn:<20}{aso:<20}{as_country:<20}")

def process_list(ip_list):
    with open(ip_list, 'r', encoding='UTF-8') as file:
        for line in file:
            print_ip_details(get_ip_info(line.rstrip()))

if ip:
    print(f"{'IP':<20}{'ASN':<20}{'ASO':<20}{'Country':<20}")
    #print_ip_details(get_ip_info(ip))
elif ip_list:
    print(f"{'IP':<20}{'ASN':<20}{'ASO':<20}{'Country':<20}")
    process_list(ip_list)
else:
    print(f"Please provide a valid argument, --help for help.")