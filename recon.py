

import socket
import requests
from config import API_KEY
from colorama import Fore, Style, init
init(autoreset=True)


print(f"{Fore.CYAN}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗        ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗")
print(f"{Fore.CYAN}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║        ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝")
print(f"{Fore.CYAN}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║        ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ")
print(f"{Fore.CYAN}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║        ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ")
print(f"{Fore.CYAN}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗")
print(f"{Fore.CYAN}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝")
print(f"{Fore.YELLOW}        Network Reconnaissance & Threat Intelligence Tool")
print(f"{Fore.YELLOW}        Built by Harsh \n")


 
                                                    # To scan the ports 

def scan_ports(target):
    
    try:
        target = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED}[ERROR] Could not resolve hostname: {target}")
        return []
    print(f"\n{Fore.CYAN}Scannning target: {target}")
    print(f"{Fore.CYAN}{'='*40}")
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP-Alt"
        }
    open_ports =[]
    for port, service in common_ports.items():
        try:
            sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result ==0:
                print(f"{Fore.GREEN}[OPEN] Port {port}-> {service}")
                sock.close()
                open_ports.append(port)
            else:
                print(f"{Fore.RED}[CLOSED] Port {port}-> {service}")
                sock.close()
        except Exception as e:
            print(f"{Fore.YELLOW}[ERROR] Port {port} -> {e}")
        
    return open_ports

                                            # To check the reputation/past-records of the IP



def check_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": API_KEY,          
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    report = data['data']
    print(f"\n{'='*40}")
    print(f"IP REPUTATION REPORT")
    print(f"{'='*40}")
    print(f"IP Address     : {report['ipAddress']}")
    print(f"Country        : {report['countryCode']}")
    print(f"ISP            : {report['isp']}")
    print(f"Abuse Score    : {report['abuseConfidenceScore']}/100")
    print(f"Total Reports  : {report['totalReports']}")
    print(f"Is Tor Node    : {report['isTor']}")
    print(f"Last Reported  : {report['lastReportedAt']}")


                                        # To generate CVE Report of the open ports


def check_cve(ports):
    print(f"\n{'='*40}")
    print(f"VULNERABILITY REPORT")
    print(f"{'='*40}")
    
    service_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "SMTP",
        53: "dns",
        80: "http",
        443: "ssl",
        3306: "mysql",
        8080: "http"
    }
    
    for port in ports:
        if port in service_map:
            keyword = service_map[port]
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 3
            }
            try:
                response = requests.get(url, params=params, timeout=10)
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                print(f"\n{Fore.YELLOW}[PORT {port} - {keyword.upper()}] Top CVEs:")
                for v in vulns:
                    cve = v["cve"]
                    cve_id = cve["id"]
                    desc = cve["descriptions"][0]["value"][:100]
                    print(f"{Fore.RED}  {cve_id}: {desc}...")
            except Exception as e:
                print(f"{Fore.YELLOW}[ERROR] CVE lookup failed for port {port}: {e}")

#target = input("Enter IP address/domain name: ")
#open_ports = scan_ports(target)
#check_ip_reputation(target)
#check_cve(open_ports)

try:
    target = input("Enter IP address/domain name: ")
    resolved_ip = socket.gethostbyname(target)
    open_ports = scan_ports(resolved_ip)
    check_ip_reputation(resolved_ip)
    check_cve(open_ports)
except KeyboardInterrupt:
    print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.")
except Exception as e:
    print(f"\n{Fore.RED}[ERROR] {e}")