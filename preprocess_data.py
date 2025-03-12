import json
import pandas as pd
import sqlite3

# Load the JSON data
with open("nvd_data.json", "r") as f:
    data = json.load(f)

# Extract relevant information
if "vulnerabilities" in data:
    cve_list = data["vulnerabilities"]
    processed_data = []

    for item in cve_list:
        cve_info = item.get("cve", {})

        # Extract severity from CVSS metrics
        severity = "Unknown"  # Default value
        metrics = cve_info.get("metrics", {})

        # Check for CVSS v2 (common format)
        if "cvssMetricV2" in metrics and isinstance(metrics["cvssMetricV2"], list):
            first_metric = metrics["cvssMetricV2"][0]  # Get first element
            severity = first_metric.get("baseSeverity", "Unknown")  # Extract severity

        processed_data.append({
            "id": cve_info.get("id", "N/A"),
            "description": cve_info.get("descriptions", [{}])[0].get("value", "No description available"),
            "published_date": cve_info.get("published", "N/A"),
            "last_modified_date": cve_info.get("lastModified", "N/A"),
            "severity": severity
        })

    # Convert to DataFrame
    df = pd.DataFrame(processed_data)

    # Save cleaned data to CSV
    df.to_csv("processed_cve_data.csv", index=False)

    # Save to SQLite database
    conn = sqlite3.connect("cybersecurity_data.db")
    df.to_sql("vulnerabilities", conn, if_exists="replace", index=False)
    conn.close()

    print("✅ Data processed and stored correctly with severity levels.")
else:
    print("⚠️ Error: 'vulnerabilities' key missing in JSON file.")
