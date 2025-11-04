# app.py
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os, time, sys, socket, uuid

# Import your scanner
from ping_arp_scan import scan_network

APP_ROOT = os.path.dirname(__file__)
ALLOW_FILE = os.path.join(APP_ROOT, "authorized_devices.txt")
NETWORK = os.getenv("NETWORK", "10.211.239.0/24")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "30"))  # seconds

app = Flask(__name__, static_folder="static")
CORS(app)

def read_allowlist():
    if not os.path.exists(ALLOW_FILE):
        return set()
    with open(ALLOW_FILE, "r") as f:
        lines = [l.strip().lower() for l in f if l.strip()]
    return set(lines)

def add_to_allowlist(mac):
    mac = mac.lower().strip()
    s = read_allowlist()
    if mac in s:
        return False
    with open(ALLOW_FILE, "a") as f:
        f.write(mac + "\n")
    return True

def get_local_ip():
    # Best-effort method to get the outbound IP of this host
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # fallback
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return ""

def get_local_mac():
    # returns local MAC in aa:bb:cc:dd:ee:ff format (best-effort)
    try:
        mac = uuid.getnode()
        mac_hex = ':'.join(("%012x" % mac)[i:i+2] for i in range(0,12,2))
        return mac_hex.lower()
    except Exception:
        return ""

LOCAL_IP = get_local_ip()
LOCAL_MAC = get_local_mac()

def scan_and_label(network_cidr=None):
    network_cidr = network_cidr or NETWORK
    print(f"[{time.ctime()}] Running scan for {network_cidr} ...", file=sys.stderr)
    try:
        devices = scan_network(network_cidr)
    except Exception as e:
        print("Scan failed:", e, file=sys.stderr)
        devices = []

    allow = read_allowlist()
    labeled = []
    for d in devices:
        ip = d.get("ip")
        mac = (d.get("mac") or "").lower()
        hostname = d.get("hostname") or ""
        # mark local device
        is_local = (ip == LOCAL_IP) or (mac and mac == LOCAL_MAC)
        if is_local and not hostname:
            try:
                hostname = socket.gethostname()
            except:
                hostname = hostname
        status = "AUTHORIZED" if (mac and mac in allow) else "UNKNOWN"
        labeled.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "status": status,
            "is_local": is_local
        })
    print(f"[{time.ctime()}] Scan returned {len(labeled)} devices.", file=sys.stderr)
    return labeled

@app.route("/api/devices")
def api_devices():
    data = scan_and_label()
    return jsonify({"devices": data, "timestamp": time.ctime(), "network": NETWORK, "local_ip": LOCAL_IP, "local_mac": LOCAL_MAC})

@app.route("/api/allow", methods=["POST"])
def api_allow():
    body = request.get_json() or {}
    mac = (body.get("mac") or "").strip().lower()
    if not mac:
        return jsonify({"status":"error","reason":"mac required"}), 400
    added = add_to_allowlist(mac)
    return jsonify({"status":"ok","added": added, "mac": mac})

# Serve static index.html (simple)
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return send_from_directory(app.static_folder, path)

if __name__ == "__main__":
    print(f"Starting app. Network: {NETWORK} Local IP: {LOCAL_IP} Local MAC: {LOCAL_MAC} Static folder: {app.static_folder}")
    app.run(host="0.0.0.0", port=5000, debug=True)
