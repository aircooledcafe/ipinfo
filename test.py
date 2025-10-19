#!/usr/bin/env python3

import requests
import json
import argparse
import urllib3
import os
from dotenv import load_dotenv

# Supress SSL warning when using verify=False to get arounod Zscaler certificate issues
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

mal_ip="144.31.221.84"
my_ip="81.109.194.142"

vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
#print(vt_api_key)
vt_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
ripe_ip_base_url = "https://rdap.db.ripe.net/ip/"
ipinfo_base_url = "https://api.ipinfo.io/lite/"

# Get IP detail from Virus Total
def get_vt_info(ip):
    headers = {'x-apikey': vt_api_key,'accept': 'application/json'}
    query_url = f"{vt_base_url}{ip}"
    res = requests.get(query_url, headers=headers, verify=False)
    data = res.json()
    #print(res.status_code)
    print(data)


def get_ripe_info(ip):
    query_url = f"{ripe_ip_base_url}{ip}?token={ip}"
    res = requests.get(query_url, verify=False)
    data = res.json()
    print(data)


# Get IP detail from IPInfo
def get_ip_info(ip):
    query_url = f"{ipinfo_base_url}{ip}?token={ip_api_key}"
    res = requests.get(query_url, verify=False)
    data = res.json()
    return data

ip_data = get_ip_info("81.109.194.142")
ripe_data = get_ripe_info("81.109.194.142")

def print_ip_details(ip_data, ripe_data):
    data = json_data
    print(data)
    ip = ip_data["ip"]
    asn = ip_data["asn"]
    aso = ip_data["as_name"]
    as_country = ip_data["country"]
    ripe_asn = ripe_data[""]
    ripe_aso = ripe_data[""]
    ripe_country = ripe_data["country"]
    print(f"{ip:<20}{asn:<20}{aso:<20}{as_country:<20}{ripe_asn:<20}{ripe_aso:<20}{ripe_country:<20}")

print(f"{'IP':<20}{'IP_ASN':<20}{'IP_ASO':<20}{'IP_Country':<20}{'RIPE_ASN':<20}{'RIPE_ASO':<20}{'RIPE_Country':<20}")
