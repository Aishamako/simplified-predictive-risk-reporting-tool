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

# Count occurrences of each severity level
severity_counts = df["severity"].value_counts()

# Create Bar Chart
plt.figure(figsize=(8, 5))
sns.barplot(x=severity_counts.index, y=severity_counts.values, palette="viridis")
plt.xlabel("Severity Level")
plt.ylabel("Count of Vulnerabilities")
plt.title("Distribution of Severity Levels")
plt.xticks(rotation=45)
plt.savefig("severity_distribution_bar.png")
plt.show()

# Create Pie Chart
plt.figure(figsize=(7, 7))
plt.pie(severity_counts, labels=severity_counts.index, autopct="%1.1f%%", colors=sns.color_palette("viridis", len(severity_counts)))
plt.title("Severity Level Distribution")
plt.savefig("severity_distribution_pie.png")
plt.show()

# Load risk predictions
risk_df = pd.read_csv("risk_predictions.csv")

# Count occurrences of each risk level
risk_counts = risk_df["risk_level"].value_counts()

# Create Risk Level Bar Chart
plt.figure(figsize=(8, 5))
sns.barplot(x=risk_counts.index, y=risk_counts.values, palette="coolwarm")
plt.xlabel("Risk Level")
plt.ylabel("Count of Vulnerabilities")
plt.title("Distribution of Risk Levels")
plt.xticks(rotation=45)
plt.savefig("risk_level_distribution.png")
plt.show()

# Extract keywords from descriptions for simple categorization (Optional)
df["category"] = df["description"].str.extract(r"(Buffer Overflow|SQL Injection|XSS|DoS|Privilege Escalation|Command Injection|Authentication Bypass)", expand=False)
df["category"].fillna("Other", inplace=True)

# Count occurrences of each category
category_counts = df["category"].value_counts().head(6)  # Show top 6

# Create Bar Chart for CVE Categories
plt.figure(figsize=(8, 5))
sns.barplot(x=category_counts.index, y=category_counts.values, palette="pastel")
plt.xlabel("CVE Categories")
plt.ylabel("Count of Vulnerabilities")
plt.title("Most Frequent CVE Categories")
plt.xticks(rotation=45)
plt.savefig("cve_categories.png")
plt.show()
