import requests
import json

# Define the NVD API URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# Function to fetch cybersecurity data
def fetch_nvd_data():
    response = requests.get(NVD_API_URL)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error fetching data: {response.status_code}")
        return None

# Fetch and print the first batch of data
if __name__ == "__main__":
    data = fetch_nvd_data()
    if data:
        with open("nvd_data.json", "w") as f:
            json.dump(data, f, indent=4)
        print("Data successfully fetched and saved to nvd_data.json")
       

