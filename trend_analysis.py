import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the cleaned CSV data
df = pd.read_csv("processed_cve_data.csv")

# Convert published_date to datetime format
df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")

# Ensure only recent CVEs (2020-2025)
df_recent = df[df["published_date"].dt.year >= 2020]

###  TREND ANALYSIS: Number of CVEs Reported Over Time ###
plt.figure(figsize=(12, 6))
df_recent["published_date"].dt.year.value_counts().sort_index().plot(kind="bar", color="skyblue")
plt.xlabel("Year")
plt.ylabel("Number of Vulnerabilities")
plt.title("Trend of Reported Vulnerabilities (2020-2025)")
plt.xticks(rotation=45)
plt.grid(axis="y", linestyle="--", alpha=0.7)

#  Save and Show Graph
plt.savefig("trend_analysis_updated.png", dpi=300)
plt.show()

###  SEVERITY DISTRIBUTION (Bar Chart) ###
severity_counts = df_recent["severity"].value_counts()

plt.figure(figsize=(8, 5))
sns.barplot(x=severity_counts.index, y=severity_counts.values, palette="viridis")
plt.xlabel("Severity Level")
plt.ylabel("Count of Vulnerabilities")
plt.title("Distribution of Severity Levels (2020-2025)")
plt.xticks(rotation=45)

#  Save and Show Graph
plt.savefig("severity_distribution_bar_updated.png")
plt.show()

###  SEVERITY DISTRIBUTION (Pie Chart) ###
plt.figure(figsize=(7, 7))
plt.pie(severity_counts, labels=severity_counts.index, autopct="%1.1f%%", colors=sns.color_palette("viridis", len(severity_counts)))
plt.title("Severity Level Distribution (2020-2025)")

#  Save and Show Graph
plt.savefig("severity_distribution_pie_updated.png")
plt.show()

###  RISK LEVEL DISTRIBUTION ###
#  Load risk predictions
risk_df = pd.read_csv("risk_predictions.csv")

#  Count occurrences of each risk level
risk_counts = risk_df["risk_level"].value_counts()

plt.figure(figsize=(8, 5))
sns.barplot(x=risk_counts.index, y=risk_counts.values, palette="coolwarm")
plt.xlabel("Risk Level")
plt.ylabel("Count of Vulnerabilities")
plt.title("Distribution of Risk Levels (2020-2025)")
plt.xticks(rotation=45)

#  Save and Show Graph
plt.savefig("risk_level_distribution_updated.png")
plt.show()

###  CVE CATEGORY ANALYSIS ###
df_recent["category"] = df_recent["description"].str.extract(r"(Buffer Overflow|SQL Injection|XSS|DoS|Privilege Escalation|Command Injection|Authentication Bypass)", expand=False)
df_recent["category"].fillna("Other", inplace=True)

#  Count occurrences of each category
category_counts = df_recent["category"].value_counts().head(6)

plt.figure(figsize=(8, 5))
sns.barplot(x=category_counts.index, y=category_counts.values, palette="pastel")
plt.xlabel("CVE Categories")
plt.ylabel("Count of Vulnerabilities")
plt.title("Most Frequent CVE Categories (2020-2025)")
plt.xticks(rotation=45)

# Save and Show Graph
plt.savefig("cve_categories_updated.png")
plt.show()
