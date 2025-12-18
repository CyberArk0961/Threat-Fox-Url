#!/usr/bin/env python3
"""
ThreatFox URL IOC Crawler
Source: https://threatfox.abuse.ch/export/csv/urls/recent/

- Fetches recent URL-based IOCs
- Handles ThreatFox CSV quirks correctly
- Outputs a fixed CSV file for automation
"""

import requests
import csv
import os
from datetime import datetime

# =====================
# CONFIG
# =====================
THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/urls/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_URL.csv"

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

# =====================
# FETCH DATA
# =====================
def fetch_threatfox_csv():
    response = requests.get(THREATFOX_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.text


# =====================
# PARSE CSV (FIXED)
# =====================
def parse_csv(raw_csv):
    records = []

    reader = csv.reader(
        line for line in raw_csv.splitlines()
        if line and not line.startswith("#")
    )

    header = next(reader, None)
    if not header:
        return records

    for row in reader:
        # ThreatFox CSV rows should have at least 8 columns
        if len(row) < 8:
            continue

        records.append({
            "ioc": row[0].strip(),
            "ioc_type": row[1].strip(),
            "threat_type": row[2].strip(),
            "malware": row[3].strip(),
            "confidence_level": row[4].strip(),
            "reference": row[5].strip(),
            "first_seen": row[6].strip(),
            "last_seen": row[7].strip(),
            "source": "ThreatFox",
            "collection_date": datetime.utcnow().isoformat()
        })

    return records


# =====================
# SAVE CSV
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    if not data:
        print("[!] No IOCs collected")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ioc",
                "ioc_type",
                "threat_type",
                "malware",
                "confidence_level",
                "reference",
                "first_seen",
                "last_seen",
                "source",
                "collection_date"
            ]
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} IOCs → {output_path}")


# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox URL IOCs...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing IOCs...")
    iocs = parse_csv(raw_csv)

    print("[*] Writing output...")
    save_csv(iocs)


if __name__ == "__main__":
    main()

