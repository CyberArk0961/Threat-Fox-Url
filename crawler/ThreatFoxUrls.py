import csv
import requests
from datetime import datetime
from io import StringIO

THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/urls/recent/"

def fetch_threatfox_urls():
    try:
        response = requests.get(THREATFOX_URL, timeout=20)
        response.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch ThreatFox data: {e}")

    csv_data = response.text

    # Remove comment lines starting with '#'
    csv_clean = "\n".join(
        line for line in csv_data.splitlines() if not line.startswith("#")
    )

    f = StringIO(csv_clean)
    reader = csv.DictReader(f)

    iocs = []
    for row in reader:
        if not row.get("ioc_value"):
            continue

        ioc_entry = {
            "ioc_value": row.get("ioc_value"),
            "ioc_type": row.get("ioc_type"),
            "threat_type": row.get("threat_type"),
            "malware_family_id": row.get("fk_malware"),
            "malware_alias": row.get("malware_alias"),
            "malware_printable": row.get("malware_printable"),
            "confidence_level": row.get("confidence_level"),
            "first_seen_utc": row.get("first_seen_utc"),
            "last_seen_utc": row.get("last_seen_utc"),
            "reference": row.get("reference"),
            "tags": row.get("tags"),
            "anonymous": row.get("anonymous"),
            "reporter": row.get("reporter"),
            "import_timestamp": datetime.utcnow().isoformat() + "Z"
        }

        iocs.append(ioc_entry)

    # Deduplicate by IOC value
    unique_iocs = {ioc["ioc_value"]: ioc for ioc in iocs}
    return list(unique_iocs.values())


def save_to_csv(iocs, filename="threatfox_urls.csv"):
    if not iocs:
        print("No IOCs to save.")
        return

    fieldnames = list(iocs[0].keys())

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(iocs)

    print(f"Saved {len(iocs)} IOCs to {filename}")


if __name__ == "__main__":
    iocs = fetch_threatfox_urls()
    print(f"Collected {len(iocs)} URL IOCs from ThreatFox")
    save_to_csv(iocs, "threatfox_urls.csv")
