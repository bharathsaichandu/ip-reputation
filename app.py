from flask import Flask, request, Response
import requests
import ipaddress
import os

app = Flask(__name__)

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VPNAPI_KEY = os.getenv("VPNAPI_KEY")

MAX_IPS = 10


def process_ip(ip):
    ipaddress.ip_address(ip)

    output = []
    output.append(f"---------------{ip} start-------------------\n")

    # -------- VirusTotal --------
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_headers = {"x-apikey": VT_API_KEY}
    vt_resp = requests.get(vt_url, headers=vt_headers, timeout=10)
    vt_data = vt_resp.json()

    stats = vt_data["data"]["attributes"]["last_analysis_stats"]
    hits = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values())

    # -------- AbuseIPDB --------
    domain = "unknown domain"
    if hits > 0:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        abuse_headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        abuse_params = {"ipAddress": ip, "maxAgeInDays": 90}
        abuse_resp = requests.get(
            abuse_url, headers=abuse_headers, params=abuse_params, timeout=10
        )
        domain = abuse_resp.json()["data"].get("domain", "unknown domain")

        output.append(f"Found {hits} out of {total} hits in VT and belongs to {domain}")
    else:
        output.append("Found clean in VT")

    output.append(f"https://www.virustotal.com/gui/ip-address/{ip}")
    output.append(f"https://www.abuseipdb.com/check/{ip}")

    # -------- VPNAPI --------
    vpn_url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
    vpn_resp = requests.get(vpn_url, timeout=10)
    vpn_data = vpn_resp.json()

    if not vpn_data.get("security"):
        output.append("No VPN detection")
    else:
        sec = vpn_data["security"]
        loc = vpn_data.get("location", {})
        net = vpn_data.get("network", {})

        output.append("VPN Detection;\n")
        output.append(f"--> ISP- {net.get('autonomous_system_organization', 'Unknown')}")
        output.append(f"--> VPN- {sec.get('vpn')}")
        output.append(f"--> Proxy- {sec.get('proxy')}")
        output.append(f"--> TOR Node- {sec.get('tor')}")
        output.append(f"--> City- {loc.get('city', 'Unknown')}")
        output.append(f"--> Region- {loc.get('region', 'Unknown')}")
        output.append(f"--> Country- {loc.get('country', 'Unknown')}")

    output.append(f"\n---------------{ip} end-------------------\n")

    return "\n".join(output)


@app.route("/check")
def check_ips():
    ips_param = request.args.get("ips")
    if not ips_param:
        return Response("Use ?ips=ip1,ip2,ip3\n", mimetype="text/plain")

    ip_list = [ip.strip() for ip in ips_param.split(",") if ip.strip()]

    if len(ip_list) > MAX_IPS:
        return Response(f"Maximum {MAX_IPS} IPs allowed\n", mimetype="text/plain")

    final_output = []
    for ip in ip_list:
        final_output.append(process_ip(ip))

    return Response("\n".join(final_output), mimetype="text/plain")


if __name__ == "__main__":
    app.run()
