# debug_scan.py
import sys, time, platform, subprocess, ipaddress, concurrent.futures, re

def ping_one(ip, timeout=500):
    system = platform.system().lower()
    ip = str(ip)
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout/1000))), ip]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode == 0
    except Exception as e:
        return False

def ping_sweep(network_cidr, max_workers=200):
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
            print("RAW arp -a output:\n", out)
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})")
            results = {}
            for m in pattern.finditer(out):
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").lower()
                results[ip] = mac
            return results
        else:
            p = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
            out = p.stdout
            print("RAW ip neigh output:\n", out)
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
            print("RAW arp -n output:\n", out)
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+([0-9a-fA-F:]{17})")
            for m in pattern.finditer(out):
                ip = m.group(1)
                mac = m.group(2).lower()
                results[ip] = mac
            return results
    except Exception as e:
        print("parse_arp_table error:", e)
        return {}

def run_debug(network):
    print("Starting debug scan for network:", network)
    t0 = time.time()
    reachable = ping_sweep(network)
    t1 = time.time()
    up = [ip for ip, r in reachable.items() if r]
    print(f"Ping sweep time: {t1-t0:.1f}s, reachable count:", len(up))
    if len(up) > 20:
        print("Sample reachable (first 20):", up[:20])
    else:
        print("Reachable hosts:", up)
    print("\nSleeping 0.7s to allow ARP table update...")
    time.sleep(0.7)
    arp = parse_arp_table()
    print("\nParsed ARP entries count:", len(arp))
    if arp:
        for k,v in list(arp.items())[:30]:
            print(k, "->", arp[k])
    devices = []
    for ip, up_flag in reachable.items():
        mac = arp.get(ip, "")
        if up_flag or mac:
            devices.append({"ip": ip, "mac": mac})
    print("\nFinal devices found count:", len(devices))
    if devices:
        for d in devices[:50]:
            print(d)
    else:
        print("[]")
    print("\nDone.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_scan.py <network_cidr>")
        sys.exit(1)
    run_debug(sys.argv[1])
