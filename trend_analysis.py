import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the cleaned CSV data
df = pd.read_csv("processed_cve_data.csv")

# Convert published_date to datetime format
df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")

# Plot trend of vulnerabilities over time
plt.figure(figsize=(12, 6))
df["published_date"].dt.year.value_counts().sort_index().plot(kind="bar", color="skyblue")
plt.xlabel("Year")
plt.ylabel("Number of Vulnerabilities")
plt.title("Trend of Reported Vulnerabilities Over Time")
plt.xticks(rotation=45)
plt.grid(axis="y", linestyle="--", alpha=0.7)

# Show and save the graph
plt.savefig("trend_analysis.png", dpi=300)
plt.show()
