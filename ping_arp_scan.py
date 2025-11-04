# ping_arp_scan.py
# Robust scanner: prefer nmap if available, otherwise fallback to ping+arp parsing.
# Returns list of dicts: [{'ip': '1.2.3.4', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': ''}, ...]

import time
import platform
import subprocess
import ipaddress
import concurrent.futures
import re

# Try to import python-nmap (optional)
try:
    import nmap
    HAVE_NMAP = True
except Exception:
    HAVE_NMAP = False

def nmap_scan(network):
    """Use python-nmap wrapper. Requires nmap binary installed on system."""
    try:
        nm = nmap.PortScanner()
        # -sn : ping scan; -n : no DNS resolution (faster)
        nm.scan(hosts=network, arguments='-sn -n')
        devices = []
        scan_dict = nm._scan_result.get('scan', {})
        for host, info in scan_dict.items():
            # ip is the host key
            ip = host
            mac = ''
            # try several places where nmap may put MAC
            # 1) info.get('addresses', {}).get('mac')
            addrs = info.get('addresses', {})
            if isinstance(addrs, dict):
                mac = addrs.get('mac', '') or addrs.get('addr', '')
            # 2) some versions put 'mac' under 'vendor' info or in 'ethernet' fields
            if not mac:
                mac = info.get('mac', '') or info.get('addresses', {}).get('ipv4','')
            mac = (mac or '').lower()
            devices.append({'ip': ip, 'mac': mac, 'hostname': ''})
        return devices
    except Exception:
        return []

# ---- fallback ping + arp parsing ----

def ping_one(ip, timeout=400):
    system = platform.system().lower()
    ip = str(ip)
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout/1000))), ip]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def ping_sweep(network_cidr, max_workers=100):
    net = ipaddress.ip_network(network_cidr, strict=False)
    ips = [str(ip) for ip in net.hosts()]
    reachable = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        futures = {ex.submit(ping_one, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                reachable[ip] = fut.result()
            except Exception:
                reachable[ip] = False
    return reachable

def parse_arp_table():
    system = platform.system().lower()
    try:
        if system == "windows":
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            out = p.stdout
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-:]{17})")
            results = {}
            for m in pattern.finditer(out):
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").lower()
                results[ip] = mac
            return results
        else:
            p = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
            out = p.stdout
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]{17})")
            results = {}
            for m in pattern.finditer(out):
                ip = m.group(1)
                mac = m.group(2).lower()
                results[ip] = mac
            if results:
                return results
            p = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            out = p.stdout
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+([0-9a-fA-F:]{17})")
            for m in pattern.finditer(out):
                ip = m.group(1)
                mac = m.group(2).lower()
                results[ip] = mac
            return results
    except Exception:
        return {}

def fallback_scan(network_cidr):
    reachable = ping_sweep(network_cidr)
    time.sleep(0.6)
    arp = parse_arp_table()
    devices = []
    for ip, up in reachable.items():
        mac = arp.get(ip, "")
        if up or mac:
            devices.append({'ip': ip, 'mac': mac, 'hostname': ''})
    return devices

def scan_network(network="192.168.1.0/24"):
    # Try nmap first
    if HAVE_NMAP:
        devices = nmap_scan(network)
        # if nmap found useful results (macs or multiple hosts), return it
        if devices and any(d.get('mac') for d in devices) or len(devices) > 3:
            return devices
    # otherwise fallback
    return fallback_scan(network)

if __name__ == "__main__":
    import sys
    net = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    print(scan_network(net))
