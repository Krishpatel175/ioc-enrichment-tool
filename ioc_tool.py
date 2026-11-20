import os 
import ipaddress
import requests 

ABUSEIPDB_URL ="https://api.abuseipdb.com/api/v2/check"

def get_ioc():
    """Ask the analyst for an indicator and return it, trimmed."""
    ioc = input("Enter an IP address: ").strip()
    return ioc

def is_valid_ip(Value): 
    """Return True if value is a valid IPv4 or IPv6 address.""" 
    try: 

        ipaddress.ip_address(Value) 
        return True 
    except ValueError: 
        return False 
    
def check_abuseipdb(ip,api_key):
    """Look up an IP on AbuseIPDB and return the JSON response."""
    headers={
        "Key": api_key,
        "Accept": "application/json",
    } 

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try: 
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
    except requests.exceptions.RequestException as error: 
        print(f"Error: could not reach AbuseIPDB ({error})")
        return None 
    if response.status_code != 200: 
        print(f"Error: AbuseIPDB returned status {response.status_code}")
        return None 
    
    return response.json() 



def main():
    print("IOC Enrichment Tool") 

    api_key =os.getenv("ABUSEIPDB_API_KEY") 
    if api_key is None: 
        print("Error: ABUSEIPDB_API_KEY is not set.")
        return
    
    
    ioc = get_ioc()

    if not is_valid_ip(ioc): 
        print(f"Error: '{ioc}' is not a valid IP address.")
        return 

    if ipaddress.ip_address(ioc).is_private: 
        print(f"{ioc} is a private/internal IP - skipping external lookup.")
        return
    
    result = check_abuseipdb(ioc, api_key) 
    if result is None: 
        return 

    data = result["data"]
    
    print() 
    print(f"--- AbuseIPDB results for {data['ipAddress']} ---") 
    print(f"Abuse score:   {data['abuseConfidenceScore' ]} / 100")
    print(f"Reports:       {data['totalReports']} (from {data['numDistinctUsers']} users)")
    print(f"Whitelisted:   {data['isWhitelisted']}")
    print(f"Tor exit node: {data['isTor' ]} ")
    print(f"Country:       {data['countryCode']}")
    print(f"ISP:           {data['isp']}") 
    print(f"Usage type:    {data['usageType']}") 
    print(f"Last reported: {data['lastReportedAt']}")


if __name__ == "__main__":
    main()