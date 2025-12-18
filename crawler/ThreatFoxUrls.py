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

        record
