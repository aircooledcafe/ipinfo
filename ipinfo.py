#!/usr/bin/env python3

import requests
import json
import argparse
import urllib3
import os
from dotenv import load_dotenv
import ipaddress

# Supress SSL warning when using verify=False to get arounod Zscaler certificate issues
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Obtain details about a give IP address or list of IP addresses")
parser.add_argument("-i", "--ipaddress", type=str, help="The IP address you want to query excluding")
parser.add_argument("-l", "--list", help="A file with a list of IP address, one per line")
parser.add_argument("-f", "--file", help="Optional: Output ASNs to a file, will be a text named after the ASN", action="store_true")
args = parser.parse_args()

load_dotenv()

ip_api_key = os.getenv('IPINFO_API_KEY')
vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
ipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
ipinfo_base_url = "https://api.ipinfo.io/lite/"
vt_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
ipdb_base_url = "https://api.abuseipdb.com/api/v2/check"

# Load args into variables
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
def get_vt_info(ip):
    headers = {'x-apikey': vt_api_key,
            'accept': 'application/json'}
    query_url = f"{vt_base_url}{ip}"
    res = requests.get(query_url, headers=headers, verify=False)
    data = res.json()
    return data

# Get IP detail from AbuseIPDB
def get_ipdb_info(ip, days):
    headers = {'Key': ipdb_api_key,
            'Accept': 'application/json'}
    params = {
        'maxAgeInDays': days,
        'ipAddress': ip
    }
    query_url = f"{ipdb_base_url}"
    res = requests.get(query_url, headers=headers, params=params, verify=False)
    data = res.json()
    return data

# calculate the percentage of reports being suspiciouso or malicious
def vt_score_calc(vt_data):
    malicious = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    suspicious = vt_data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
    undetected = vt_data["data"]["attributes"]["last_analysis_stats"]["undetected"]
    harmless = vt_data["data"]["attributes"]["last_analysis_stats"]["harmless"]
    timeout = vt_data["data"]["attributes"]["last_analysis_stats"]["timeout"]
    total = malicious + suspicious + undetected + harmless + timeout
    sus = malicious + suspicious
    score = "{:.2%}".format(sus / total)
    return score

# Print IP infor to console:
def print_ip_details(ip_data, vt_data, ipdb_data):
    ip = ip_data["ip"]
    asn = ip_data["asn"]
    aso = ip_data["as_name"]
    as_domain = ip_data["as_domain"]
    ip_country = ip_data["country"]
    as_country_code = ip_data["country_code"]
    #vt_link = vt_data["data"]["links"]["self"]
    vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
    vt_reputation = vt_data["data"]["attributes"]["reputation"]
    vt_country = ""
    try:
        vt_country = vt_data["data"]["attributes"]["country"]
    except KeyError:
        vt_country = "--"
    vt_asn = vt_data["data"]["attributes"]["asn"]
    vt_aso = vt_data["data"]["attributes"]["as_owner"]
    vt_score = vt_score_calc(vt_data)
    ipdb_score = ipdb_data["data"]["abuseConfidenceScore"]
    ipdb_country_code = ipdb_data["data"]["countryCode"]
    print(f"{ip:<20}{ip_country:<20}{as_country_code:<10}{vt_country:<10}{ipdb_country_code:<10}{asn:<15}{aso:<30}{vt_reputation:<10}{vt_score:<10}{ipdb_score:<15}{vt_link}")

def process_list(ip_list):
    with open(ip_list, 'r', encoding='UTF-8') as file:
        internal = []
        for line in file:
            if ipaddress.ip_address(line.rstrip()).is_private:
                internal.append(line.rstrip())
            else:    
                print_ip_details(get_ip_info(line.rstrip()), get_vt_info(line.rstrip()), get_ipdb_info(line.rstrip(), 90))
        print(f"\nThe following IP are not public and were ingnored:")
        print(internal)

if ip:
    if ipaddress.ip_address(ip).is_private:
        print(f"{ip} is am RFC1918 reserved IP address.")
        exit()
    else:
        print(f"{'IP':<20}{'Country':<20}{'IP_Code':<10}{'VT_Code':<10}{'IPDB_Code':<10}{'ASN':<15}{'ASO':<30}{'VT_Rep':<10}{'VT_Score':<10}{'AIPDB_Score':<15}{'VT_Link'}")
        print_ip_details(get_ip_info(ip), get_vt_info(ip), get_ipdb_info(ip, 90))
elif ip_list:
    print(f"{'IP':<20}{'Country':<20}{'IP_Code':<10}{'VT_Code':<10}{'IPDB_Code':<10}{'ASN':<15}{'ASO':<30}{'VT_Rep':<10}{'VT_Score':<10}{'AIPDB_Score':<15}{'VT_Link'}")
    process_list(ip_list)
else:
    print(f"Please provide a valid argument, --help for help.")