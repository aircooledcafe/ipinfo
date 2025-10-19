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
ipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
#print(vt_api_key)
vt_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
ripe_ip_base_url = "https://rdap.db.ripe.net/ip/"
ipinfo_base_url = "https://api.ipinfo.io/lite/"
ipdb_base_url = "https://api.abuseipdb.com/api/v2/check"

# Get IP detail from Virus Total
def get_vt_info(ip):
    headers = {'x-apikey': vt_api_key,'accept': 'application/json'}
    query_url = f"{vt_base_url}{ip}"
    res = requests.get(query_url, headers=headers, verify=False)
    data = res.json()
    #print(res.status_code)
    return data


def get_ripe_info(ip):
    query_url = f"{ripe_ip_base_url}{ip}?token={ip}"
    res = requests.get(query_url, verify=False)
    data = res.json()
    return data


# Get IP detail from IPInfo
def get_ip_info(ip):
    query_url = f"{ipinfo_base_url}{ip}?token={ip_api_key}"
    res = requests.get(query_url, verify=False)
    data = res.json()
    return data

#ip_data = get_ip_info("81.109.194.142")
#ripe_data = get_ripe_info("81.109.194.142")
#vt_data= get_vt_info("81.109.194.142")

def print_vt_details(vt_data):
    #print(vt_data)
    ip = vt_data["data"]["id"]
    vt_link = vt_data["data"]["links"]["self"]
    reputation_score = vt_data["data"]["attributes"]["reputation"]
    vt_country = vt_data["data"]["attributes"]["country"]
    vt_asn = vt_data["data"]["attributes"]["asn"]
    vt_aso = vt_data["data"]["attributes"]["as_owner"]
    print(f"{ip:<20}{reputation_score:<15}{vt_country:<15}{vt_asn:<10}{vt_aso:<30}{vt_link}")
    
def vt_score(vt_data):
    malicious = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    suspicious = vt_data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
    undetected = vt_data["data"]["attributes"]["last_analysis_stats"]["undetected"]
    harmless = vt_data["data"]["attributes"]["last_analysis_stats"]["harmless"]
    timeout = vt_data["data"]["attributes"]["last_analysis_stats"]["timeout"]
    total = malicious + suspicious + undetected + harmless + timeout
    sus = malicious + suspicious
    score = "{:.2%}".format(sus / total)
    return score
    
#print(f"{'IP':<20}{'VT_Score':<15}{'VT_Country':<15}{'VT_ASN':<10}{'VT_ASO':<30}{'VT_LINK'}")
#print_vt_details(get_vt_info(mal_ip))
#print_vt_details(get_vt_info("1.1.1.1"))
#print_vt_details(get_vt_info(my_ip))
# vt_score(get_vt_info(mal_ip))


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
print(get_ipdb_info(mal_ip, 90))