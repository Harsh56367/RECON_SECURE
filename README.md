# RECON_SECURE 

A  tool for network reconnaissance and threat intelligence. Built this as a project to learn python Socket programming and Basic network security concepts.

# What it does

- Scans common ports on a target IP or domain and checks which ones are open
- Checks the IP reputation using AbuseIPDB database (tells you if the IP has been reported for malicious activity)
- Pulls up recent CVEs (known vulnerabilities) for whatever services are running on the open ports using NVD database

basically it automates the first phase of a pentest which is reconnaissance.

## Tools and APIs used

- AbuseIPDB API - for threat intelligence
- NVD (National Vulnerability Database) API - for CVE lookup
- Python socket library - for port scanning
- colorama - for the terminal colors

## How to run it

First clone the repo
```
git clone https://github.com/Harsh56367/RECON_SECURE.git
```

Install the dependencies
```
pip install requests colorama
```

Create a config.py file in the same folder and add your AbuseIPDB API key
```
API_KEY = "your_api_key_here"
```
 you can get a free key from abuseipdb.com

Then just run it
python recon.py

## Legal stuff

Only use this on IPs and domains you have permission to scan(you can find plenty of them on abuseipdb.com to experiment with). Scanning without permission is illegal.

## What I learned
- Networking basics, TCP handshake, IPV4 , CVE , about different ports and their basic functionality and how data transfer actually happens
- How TCP connections and port scanning actually works
- How to work with REST APIs in python
- Python Socket programming.
- About network reconnaissance and threat intelligence
- How CVEs and vulnerability databases work


---
Built by Harsh  | B.Tech CSE(Cybersecurity & IoT) | Heritage Institute of Technology
