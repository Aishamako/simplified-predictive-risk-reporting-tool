import os
import requests
from flask import Blueprint, request, jsonify
from dotenv import load_dotenv

load_dotenv()

virustotal_bp = Blueprint("virustotal", __name__)
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

@virustotal_bp.route("/api/virustotal", methods=["POST"])
def virustotal_lookup():
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Missing 'domain' in request"}), 400

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        categories = result.get("data", {}).get("attributes", {}).get("categories", {})
        last_analysis = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return jsonify({
            "domain": domain,
            "categories": categories,
            "analysis": last_analysis
        })
    else:
        return jsonify({"error": "VirusTotal API call failed"}), 500
