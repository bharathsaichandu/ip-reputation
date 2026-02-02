from flask import Flask, request, Response, render_template_string
import os
import requests
import socket
import asyncio
import aiohttp

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VPNAPI_KEY = os.getenv("VPNAPI_KEY")

app = Flask(__name__)

MAX_IPS = 10

# ---------------- Async processing for one IP ----------------
async def fetch_json(session, url, headers=None, params=None):
    async with session.get(url, headers=headers, params=params, timeout=15) as resp:
        return await resp.json()

async def process_ip(ip):
    output = []
    output.append(f"---------------{ip} start-------------------\n")

    vt_hits = 0
    domain = "No domain associated"
    isp = "Unknown ISP"
    try:
        async with aiohttp.ClientSession() as session:
            # -------- VirusTotal --------
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            vt_headers = {"x-apikey": VT_API_KEY}
            vt_data = await fetch_json(session, vt_url, headers=vt_headers)
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_hits = sum(stats.values()) if stats else 0

            # -------- AbuseIPDB --------
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            abuse_headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
            abuse_params = {"ipAddress": ip, "maxAgeInDays": 90}
            abuse_data = await fetch_json(session, abuse_url, headers=abuse_headers, params=abuse_params)
            abuse_info = abuse_data.get("data", {})
            domain = abuse_info.get("domain") or (abuse_info.get("hostnames")[0] if abuse_info.get("hostnames") else None)
            if not domain:
                try:
                    domain = socket.gethostbyaddr(ip)[0]
                except Exception:
                    domain = "No domain associated"
            isp = abuse_info.get("isp", "Unknown ISP")

            # -------- VPNAPI --------
            vpn_url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
            vpn_data = await fetch_json(session, vpn_url)
            sec = vpn_data.get("security", {})
            loc = vpn_data.get("location", {})
            net = vpn_data.get("network", {})
    except Exception:
        sec = {}
        loc = {}
        net = {}

    vt_msg = f"Found {vt_hits} out of 93 hits in VT" if vt_hits else "Found clean in VT"
    output.append(f"{vt_msg} and belongs to {domain}")
    output.append(f"https://www.virustotal.com/gui/ip-address/{ip}")
    output.append(f"https://www.abuseipdb.com/check/{ip}")

    if not sec:
        output.append("No VPN detection")
    else:
        output.append("VPN Detection;\n")
        output.append(f"--> ISP- {isp}")
        output.append(f"--> VPN- {sec.get('vpn', False)}")
        output.append(f"--> Proxy- {sec.get('proxy', False)}")
        output.append(f"--> TOR Node- {sec.get('tor', False)}")
        output.append(f"--> City- {loc.get('city', '')}")
        output.append(f"--> Region- {loc.get('region', '')}")
        output.append(f"--> Country- {loc.get('country', 'Unknown')}")

    output.append(f"\n---------------{ip} end-------------------\n")
    return "\n".join(output)

# ---------------- Flask routes ----------------
@app.route("/")
def home():
    return "IP Reputation Service is running!"

@app.route("/check")
def check_ips():
    ips_param = request.args.get("ips")
    if not ips_param:
        return Response("Please provide IPs as query parameter, e.g., ?ips=8.8.8.8,149.88.25.228", mimetype="text/plain")

    ip_list = [ip.strip() for ip in ips_param.split(",") if ip.strip()]
    if len(ip_list) > MAX_IPS:
        return Response(f"Maximum {MAX_IPS} IPs allowed\n", mimetype="text/plain")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(asyncio.gather(*(process_ip(ip) for ip in ip_list)))
    return Response("\n".join(results), mimetype="text/plain")

@app.route("/ui")
def ui():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>IP Reputation Checker</title>
    <style>
        body {
            background-color: #1e1e1e;
            color: #f5f5f5;
            font-family: monospace;
            padding: 30px;
        }
        h3 {
            margin-bottom: 20px;
        }
        textarea {
            background-color: #2b2b2b;
            color: #f5f5f5;
            font-family: monospace;
            font-size: 16px;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #555555;
            width: 100%;
            box-sizing: border-box;
            resize: vertical;
        }
        button {
            background-color: #3a3a3a;
            color: #f5f5f5;
            font-family: monospace;
            font-size: 16px;
            padding: 12px 24px;
            border-radius: 8px;
            border: 1px solid #555555;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-right: 10px;
        }
        button:hover {
            background-color: #555555;
            color: #ffffff;
        }
        #output {
            display: none;
            margin-top: 25px;
            white-space: pre-wrap;
            background-color: #2c2c2c;
            color: #f5f5f5;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #555555;
            overflow-x: auto;
            max-height: 500px;
        }
    </style>
</head>
<body>

<h3>IP Reputation Checker</h3>

<textarea id="ips" rows="4" placeholder="Enter IPs separated by commas"></textarea>
<br><br>

<button onclick="checkIPs()">Check</button>
<button id="copyBtn" onclick="copyOutput()" style="display:none;">Copy</button>

<div id="output"></div>

<script>
function checkIPs() {
    const ips = document.getElementById("ips").value.trim();
    const outputDiv = document.getElementById("output");
    const copyBtn = document.getElementById("copyBtn");
    
    if(!ips) return;

    outputDiv.style.display = "block";  
    outputDiv.innerHTML = "Checking...";
    copyBtn.style.display = "none";  

    fetch("/check?ips=" + encodeURIComponent(ips))
        .then(res => res.text())
        .then(data => {
            outputDiv.innerHTML = data;
            copyBtn.style.display = "inline-block";  
        })
        .catch(err => {
            outputDiv.innerHTML = "Error: " + err;
            copyBtn.style.display = "none";
        });
}

function copyOutput() {
    const outputDiv = document.getElementById("output");
    navigator.clipboard.writeText(outputDiv.innerText); // copy silently
}
</script>

</body>
</html>
"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
