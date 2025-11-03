import json
import datetime
import logging
import requests
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# API keys from .env
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")  # AbuseIPDB API key
OTX_API_KEY = os.getenv("OTX_API_KEY")  # AlienVault OTX API key

# Input and output files
INPUT_FILE = "threat_indicators.txt"  # List of IPs/domains/hashes
OUTPUT_JSON = "threat_report.json"  # Report output
LOG_FILE = "script.log"  # Log file

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Check IP reputation on AbuseIPDB
def check_ip_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        r = requests.get(url, headers=headers)  # Make request

        # Non-200 response handling
        if r.status_code != 200:
            logging.warning(f"AbuseIPDB error: {r.status_code}")
            return {"ip": ip, "error": r.status_code}

        # Extract abuse confidence score
        score = r.json().get("data", {}).get("abuseConfidenceScore", 0)
        logging.info(f"{ip} -> Abuse Score {score}")
        return {"ip": ip, "abuse_score": score}

    except Exception as e:
        logging.error(e)
        return {"ip": ip, "error": "API failure"}

# Check domain reputation on AlienVault OTX
def check_otx_reputation(indicator):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(url, headers=headers)  # Make request

        # Non-200 response handling
        if r.status_code != 200:
            logging.warning(f"OTX error for {indicator}: {r.status_code}")
            return {"indicator": indicator, "error": r.status_code}

        # Extract number of threat pulses
        pulses = r.json().get("pulse_info", {}).get("count", 0)
        logging.info(f"{indicator} -> Pulses {pulses}")
        return {"indicator": indicator, "threat_pulses": pulses}

    except Exception as e:
        logging.error(e)
        return {"indicator": indicator, "error": "API failure"}

# Main analysis function
def analyze_indicators():
    print("\nOSINT scan started...\n")
    logging.info("OSINT scan start")

    try:
        # Read indicators from file
        with open(INPUT_FILE) as f:
            indicators = [i.strip() for i in f if i.strip()]  # remove blank lines

        results = []

        # Loop through each indicator
        for ind in indicators:
            if ind.count(".") >= 2:  # crude IP/domain check
                results.append(check_ip_abuseipdb(ind))  # IP check
            else:
                results.append(check_otx_reputation(ind))  # domain/hash check

        # Create report dictionary
        report = {
            "results": results,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # current time
        }

        # Print report
        print(json.dumps(report, indent=4))

        # Save report to JSON file
        with open(OUTPUT_JSON, "w") as f:
            json.dump(report, f, indent=4)

        print(f"Report saved -> {OUTPUT_JSON}")
        logging.info("Scan complete")

    except FileNotFoundError:
        print("Input indicators file missing")
        logging.error("Missing input file")
    except Exception as e:
        print("Unexpected error")
        logging.error(e)

# Execute script
if __name__ == "__main__":
    analyze_indicators()
