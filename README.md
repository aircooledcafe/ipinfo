## IPInfo
  
A python script ofr obtaining detailed infomration about IP addresses.  
..
#### Requirements
  
IPInfo API Key `https://ipinfo.io/dashboard/token`.  
VirusTotal API Key `https://www.virustotal.com/gui/user/$USER_NAME/apikey`.  
AbuseIPDB API Key `https://www.abuseipdb.com/account/api`.  
  
Your credentials will need to be stored in a `.env` file in the local directory, in the following format:  
```
IPINFO_API_KEY = "KEY"
VIRUSTOTAL_API_KEY = "KEY"
ABUSEIPDB_API_KEY = "KEY"
```
  
The following python packages are required:  
requests
json
argparse
urllib3
dotenv
ipaddress
  
```pip install requests json argparse urllib3 dotenv ipaddress```