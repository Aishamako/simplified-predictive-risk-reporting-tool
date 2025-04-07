import os
import requests
from flask import Blueprint, request, jsonify
from dotenv import load_dotenv

load_dotenv()

shodan_bp = Blueprint("shodan", __name__)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

@shodan_bp.route("/api/shodan", methods=["POST"])
def shodan_lookup():
    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "Missing 'ip' in request"}), 400

    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = requests.get(url)

    if response.status_code == 200:
        result = response.json()
        return jsonify({
            "ip": result.get("ip_str"),
            "organization": result.get("org"),
            "os": result.get("os"),
            "ports": result.get("ports"),
            "hostnames": result.get("hostnames"),
            "vulns": result.get("vulns", [])
        })
    else:
        return jsonify({"error": "Shodan API call failed"}), 500
