import pandas as pd
import numpy as np

# Load the preprocessed data
df = pd.read_csv("processed_cve_data.csv")

# Ensure necessary columns exist
if "published_date" in df.columns and "severity" in df.columns:
    
    # Convert published_date to datetime for analysis
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")

    # Rule-based risk prediction (basic approach)
    def predict_risk(severity):
        print(f"Processing severity: {severity}")  # Debugging line
        if severity in ["Critical", "High"]:
            return "High Risk"
        elif severity in ["Medium"]:
            return "Moderate Risk"
        elif severity in ["Low"]:
            return "Low Risk"
        else:
            return "Unknown Risk"
    print(df["severity"].unique())  # Check severity values
    df["severity"] = df["severity"].str.strip().str.capitalize()
    
    # Apply risk prediction
    df["risk_level"] = df["severity"].apply(predict_risk)

    # Save results
    df.to_csv("risk_predictions.csv", index=False)
    print(" Risk predictions saved to 'risk_predictions.csv'")

else:
    print("⚠️ Error: Required columns missing in processed data.")

print(df[['severity', 'risk_level']].head(10))
