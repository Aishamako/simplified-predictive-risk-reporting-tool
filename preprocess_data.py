import json
import pandas as pd
import sqlite3

# Load the JSON data
with open("nvd_data.json", "r") as f:
    data = json.load(f)

# Extract relevant information from the correct key
if "vulnerabilities" in data:
    cve_list = data["vulnerabilities"]
    processed_data = []

    for item in cve_list:
        cve_info = item.get("cve", {})
        processed_data.append({
            "id": cve_info.get("id", "N/A"),
            "description": cve_info.get("descriptions", [{}])[0].get("value", "No description available"),
            "published_date": cve_info.get("published", "N/A"),
            "last_modified_date": cve_info.get("lastModified", "N/A"),
            "severity": cve_info.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseSeverity", "Unknown")
        })

    # Convert to DataFrame
    df = pd.DataFrame(processed_data)

    # Save processed data to CSV for easy access
    df.to_csv("processed_cve_data.csv", index=False)
    print("✅ Data successfully processed and saved as 'processed_cve_data.csv'")

    # 🔹 DATA CLEANING STARTS HERE 🔹
    
    # Drop duplicate entries based on 'id'
    df.drop_duplicates(subset="id", keep="first", inplace=True)

    # Fill missing severity levels with "Unknown"
    df["severity"].fillna("Unknown", inplace=True)

    # Save cleaned data to CSV for easy access
    df.to_csv("processed_cve_data.csv", index=False)

    # Save cleaned data to SQLite database
    conn = sqlite3.connect("cybersecurity_data.db")
    df.to_sql("vulnerabilities", conn, if_exists="replace", index=False)
    conn.close()

    print("Data successfully processed, cleaned, and stored in 'processed_cve_data.csv' and 'cybersecurity_data.db'")

else:
    print("Error: 'vulnerabilities' key missing in JSON file.")
