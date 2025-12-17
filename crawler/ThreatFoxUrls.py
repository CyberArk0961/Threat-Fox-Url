import csv
import requests
from datetime import datetime
from io import StringIO

THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/urls/recent/"

def fetch_threatfox_urls():
    """
    Fetches recent URL IOCs from ThreatFox CSV export.
    Returns a list of dictionaries with normalized fields.
    """

    try:
        response = requests.get(THREATFOX_URL, timeout=20)
        response.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch ThreatFox data: {e}")

    csv_data = response.text

    # ThreatFox CSV contains comment lines starting with '#'
    csv_clean = "\n".join(
        line for line in csv_data.splitlines() if not line.startswith("#")
    )

    f = StringIO(csv_clean)
    reader = csv.DictReader(f)

    iocs = []
    for row in reader:
        ioc_entry = {
            "ioc_value": row.get("ioc_value"),
            "threat_type": row.get("threat_type"),
            "malware": row.get("malware"),
            "confidence_level": row.get("confidence_level"),
            "first_seen_utc": row.get("first_seen_utc"),
            "last_seen_utc": row.get("last_seen_utc"),
            "reference": row.get("reference"),
            "import_timestamp": datetime.utcnow().isoformat() + "Z"
        }
        iocs.append(ioc_entry)

    # Deduplicate by IOC value
    unique_iocs = {ioc["ioc_value"]: ioc for ioc in iocs}
    return list(unique_iocs.values())


if __name__ == "__main__":
    iocs = fetch_threatfox_urls()
    print(f"Collected {len(iocs)} URL IOCs from ThreatFox\n")

    for i in iocs[:10]:  # preview first 10
        print(i)
