import sqlite3
import json

# Connect to SQLite database
conn = sqlite3.connect("cybersecurity_data.db")
cursor = conn.cursor()

# Create table if it doesn’t exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        description TEXT,
        published_date TEXT,
        last_modified_date TEXT,
        severity TEXT
    )
""")

# Read the fetched data from JSON file
with open("nvd_data.json", "r") as f:
    data = json.load(f)

vulnerabilities = data.get("result", {}).get("CVE_Items", [])

# Insert data into SQLite
for item in vulnerabilities:
    cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "N/A")
    description = item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "No description")
    published_date = item.get("publishedDate", "N/A")
    last_modified_date = item.get("lastModifiedDate", "N/A")
    severity = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "Unknown")

    cursor.execute("""
        INSERT OR IGNORE INTO vulnerabilities (id, description, published_date, last_modified_date, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (cve_id, description, published_date, last_modified_date, severity))

# Commit and close connection
conn.commit()
conn.close()
print("Data successfully stored in SQLite database.")
