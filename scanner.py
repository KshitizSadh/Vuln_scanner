import nmap
import socket
import requests
import argparse

def scan_ports(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target} for open ports...")

    results = {}

    try:
        scanner.scan(target, arguments="-sV -p 1-65535")
        
        for host in scanner.all_hosts():
            results[host] = {}
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                
                for port in ports:
                    service = scanner[host][proto][port]
                    results[host][port] = {
                        "state": service["state"],
                        "name": service["name"],
                        "version": service.get("version", "Unknown")
                    }
    except Exception as e:
        print(f"Error scanning {target}: {e}")

    return results

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024).decode().strip()
            return banner
    except Exception:
        return None

def check_vulnerabilities(service, version):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service} {version}"
    
    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if "result" in data and "CVE_Items" in data["result"]:
            cves = [item["cve"]["CVE_data_meta"]["ID"] for item in data["result"]["CVE_Items"]]
            return cves if cves else ["No vulnerabilities found."]
    except Exception as e:
        return [f"Error fetching CVE data: {e}"]
    
    return ["No vulnerabilities found."]

def main():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or Domain to scan")
    args = parser.parse_args()

    scan_results = scan_ports(args.target)
    print("\n---- Scan Results ----")
    
    for host, ports in scan_results.items():
        print(f"\nHost: {host}")
        
        for port, details in ports.items():
            print(f"[{port}] {details['name']} {details['version']} ({details['state']})")

            banner = grab_banner(host, port)
            if banner:
                print(f"  - Banner: {banner}")

            cves = check_vulnerabilities(details['name'], details['version'])
            print(f"  - CVEs: {', '.join(cves)}")

if __name__ == "__main__":
    main()
