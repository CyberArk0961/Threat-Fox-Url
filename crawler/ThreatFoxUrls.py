#!/usr/bin/env python3
"""
ThreatFox URL IOC Crawler
Source: https://threatfox.abuse.ch/export/csv/urls/recent/

- Fetches recent URL-based IOCs
- Cleans CSV comments
- Outputs structured CSV
- Safe for daily automation
"""

import requests
import csv
import io
from datetime import datetime
import os

# =====================
# CONFIG
# =====================
THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/urls/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = f"threatfox_urls_{datetime.utcnow().strftime('%Y%m%d')}.csv"

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

# =====================
# FUNCTIONS
# =====================
def fetch_threatfox_csv():
    response = requests.get(THREATFOX_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.text


def parse_csv(raw_csv):
    """
    ThreatFox CSV contains comment lines starting with '#'
    """
    clean_lines = [
        line for line in raw_csv.splitlines()
        if not line.startswith("#") and line.strip()
    ]

    reader = csv.DictReader(clean_lines)
    records = []

    for row in reader:
        records.append({
            "ioc": row.get("ioc"),
            "ioc_type": row.get("ioc_type"),
            "threat_type": row.get("threat_type"),
            "malware": row.get("malware"),
            "confidence_level": row.get("confidence_level"),
            "reference": row.get("reference"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "source": "ThreatFox",
            "collection_date": datetime.utcnow().isoformat()
        })

    return records


def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    if not data:
        print("[!] No IOCs collected")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} URL IOCs → {output_path}")


# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox URL IOCs...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing data...")
    iocs = parse_csv(raw_csv)

    print("[*] Saving output...")
    save_csv(iocs)


if __name__ == "__main__":
    main()
