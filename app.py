from flask import Flask, request
import os
import requests
from dotenv import load_dotenv
import socket

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VPNAPI_KEY = os.getenv("VPNAPI_KEY")

app = Flask(__name__)

# Function to process a single IP
def process_ip(ip):
    output = []
    output.append(f"---------------{ip} start-------------------\n")

    # ---------------- VirusTotal ----------------
    vt_hits = 0
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        vt_response = requests.get(vt_url, headers=headers)
        vt_data = vt_response.json()
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_hits = sum(stats.values()) if stats else 0
    except Exception:
        vt_hits = 0

    vt_msg = f"Found {vt_hits} out of 93 hits in VT" if vt_hits else "Found clean in VT"

    # ---------------- AbuseIPDB ----------------
    domain = "No domain associated"
    try:
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        abuse_resp = requests.get(abuse_url, headers=headers).json()
        abuse_data = abuse_resp.get("data", {})
        # Use domain from API or reverse DNS fallback
        domain = abuse_data.get("domain") or abuse_data.get("hostnames", [])
        if isinstance(domain, list) and domain:
            domain = domain[0]
        elif isinstance(domain, list) and not domain:
            # fallback to reverse DNS
            try:
                domain = socket.gethostbyaddr(ip)[0]
            except Exception:
                domain = "No domain associated"
        elif not domain:
            try:
                domain = socket.gethostbyaddr(ip)[0]
            except Exception:
                domain = "No domain associated"
        isp = abuse_data.get("isp", "Unknown ISP")
    except Exception:
        isp = "Unknown ISP"

    output.append(f"{vt_msg} and belongs to {domain}")
    output.append(f"https://www.virustotal.com/gui/ip-address/{ip}")
    output.append(f"https://www.abuseipdb.com/check/{ip}")

    # ---------------- VPNAPI ----------------
    vpn_output = []
    try:
        vpn_url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
        vpn_resp = requests.get(vpn_url).json()
        vpn_data = vpn_resp.get("security", {})
        loc_data = vpn_resp.get("location", {})
        vpn_output.append("VPN Detection;\n")
        vpn_output.append(f"--> ISP- {isp}")
        vpn_output.append(f"--> VPN- {vpn_data.get('vpn', False)}")
        vpn_output.append(f"--> Proxy- {vpn_data.get('proxy', False)}")
        vpn_output.append(f"--> TOR Node- {vpn_data.get('tor', False)}")
        vpn_output.append(f"--> City- {loc_data.get('city', 'Unknown')}")
        vpn_output.append(f"--> Region- {loc_data.get('region', 'Unknown')}")
        vpn_output.append(f"--> Country- {loc_data.get('country', 'Unknown')}")
    except Exception:
        vpn_output.append("No VPN detection")

    output.extend(vpn_output)
    output.append(f"---------------{ip} end-------------------\n")
    return "\n".join(output)

# Route for health check
@app.route("/")
def home():
    return "IP Reputation Service is running!"

# Route to check IPs
@app.route("/check")
def check_ips():
    ips_param = request.args.get("ips")
    if not ips_param:
        return "Please provide IPs as query parameter, e.g., ?ips=8.8.8.8,149.88.25.228"

    ip_list = [ip.strip() for ip in ips_param.split(",")]
    final_output = []
    for ip in ip_list:
        final_output.append(process_ip(ip))

    return "<pre>" + "\n".join(final_output) + "</pre>"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
