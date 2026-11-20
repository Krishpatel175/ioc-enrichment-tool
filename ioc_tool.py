import os 
import requests 

ABUSEIPDB_URL ="https://api.abuseipdb.com/api/v2/check"

def get_ioc():
    """Ask the analyst for an indicator and return it, trimmed."""
    ioc = input("Enter an IP address: ").strip()
    return ioc

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
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10 )
    print("Status code:", response.status_code) 
    return response.json() 



def main():
    print("IOC Enrichment Tool") 

    api_key =os.getenv("ABUSEIPDB_API_KEY") 
    if api_key is None: 
        print("Error: ABUSEIPDB_API_KEY is not set.")
        return
    
    
    ioc = get_ioc()
    result = check_abuseipdb(ioc, api_key) 


    data = result["data"] 
    print() 
    print(f"--- AbuseIPDB results for {data['ipAddress']} ---") 
    print(f"Abuse score:   {data['abuseConfidenceScore' ]} / 100")
    print(f"Reports:       {data['totalReports']} (from{data['numDistinctUsers']} users)")
    print(f"Whitelisted:   {data['isWhitelisted']}")
    print(f"Tor exit node: {data['isTor' ]} ")
    print(f"Country:       {data['countryCode']}")
    print(f"ISP:           {data['isp']}") 
    print(f"Usage type:    {data['usageType']}") 
    print(f"Last reported: {data['lastReportedAt']}")


if __name__ == "__main__":
    main()