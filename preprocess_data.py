import json
import pandas as pd
import sqlite3

# Load the JSON data
with open("nvdcve-1.1-modified.json", "r") as f:
    data = json.load(f)

# Extract relevant information
if "vulnerabilities" in data:
    cve_list = data["vulnerabilities"]
elif "CVE_Items" in data:  # ✅ New format in NVD dataset
    cve_list = data["CVE_Items"]
else:
    print("⚠️ Error: No valid CVE data found.")
    exit()

processed_data = []

for item in cve_list:
    cve_info = item.get("cve", {})

    # ✅ Extract CVE ID (Updated for new format)
    cve_id = cve_info.get("CVE_data_meta", {}).get("ID", "N/A")

    # ✅ Extract description (Updated for new format)
    descriptions = cve_info.get("description", {}).get("description_data", [{}])
    description = descriptions[0].get("value", "No description available")

    # ✅ Extract severity from CVSS metrics (v2 & v3)
    severity = "Unknown"
    impact = item.get("impact", {})

    if "baseMetricV3" in impact:  # CVSS v3
        severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "Unknown")
    elif "baseMetricV2" in impact:  # CVSS v2
        severity = impact["baseMetricV2"].get("cvssV2", {}).get("baseSeverity", "Unknown")

    # ✅ Append filtered CVEs from 2020+
    published_date = item.get("publishedDate", "N/A")
    if published_date != "N/A" and int(published_date[:4]) >= 2020:
        processed_data.append({
            "id": cve_id,
            "description": description,
            "published_date": published_date,
            "last_modified_date": item.get("lastModifiedDate", "N/A"),
            "severity": severity
        })

# Convert to DataFrame
df = pd.DataFrame(processed_data)

if not df.empty:
    # ✅ Save cleaned data to CSV
    df.to_csv("processed_cve_data.csv", index=False)

    # ✅ Save to SQLite database
    conn = sqlite3.connect("cybersecurity_data.db")
    df.to_sql("vulnerabilities", conn, if_exists="replace", index=False)
    conn.close()

    print(f"✅ Data processed and stored correctly with {len(df)} CVEs from 2020+.")
else:
    print("⚠️ No CVEs from 2020+ found. No data stored.")
