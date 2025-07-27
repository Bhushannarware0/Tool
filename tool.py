#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Import required libraries
import argparse
import socket
import subprocess
import requests
import ipaddress
import platform
from concurrent.futures import ThreadPoolExecutor

# ---------------- URL harmful check ----------------
def check_url_harmful(url):
    # Simple blacklist example
    blacklisted_domains = ["phishing.com", "malware-site.org", "badurl.net"]
    for domain in blacklisted_domains:
        if domain in url:
            return True
    return False

def get_redirect_chain(url):
    # Get all redirects of the URL
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        return [resp.url for resp in response.history] + [response.url]
    except Exception as e:
        return [f"Error: {e}"]

# ---------------- DNS Lookup + GeoIP ----------------
def dns_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Hostname not found"

def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        return {
            "IP": data.get("ip"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Country": data.get("country"),
            "Org": data.get("org"),
            "Loc": data.get("loc"),
        }
    except Exception as e:
        return {"error": str(e)}

# ---------------- Nmap Scan ----------------
def run_nmap(target):
    print(f"Running nmap scan on {target}...")
    try:
        result = subprocess.run(['nmap', target], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e}")

# ---------------- Whois Lookup ----------------
def run_whois(target):
    print(f"Running whois lookup on {target}...")
    try:
        result = subprocess.run(['whois', target], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running whois: {e}")

# ---------------- Traceroute ----------------
def run_traceroute(target):
    print(f"Running traceroute on {target}...")
    try:
        cmd = "traceroute" if platform.system() != "Windows" else "tracert"
        result = subprocess.run([cmd, target], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running traceroute: {e}")

# ---------------- Ping Sweep ----------------
def ping_ip(ip):
    # Ping ek baar send karta hai host ko
    param = "-n" if platform.system() == "Windows" else "-c"
    command = ['ping', param, '1', str(ip)]
    result = subprocess.run(command, stdout=subprocess.DEVNULL)
    return (str(ip), result.returncode == 0)

def ping_sweep(subnet):
    print(f"Pinging all IPs in subnet {subnet} ...")
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print("Invalid subnet!")
        return
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(ping_ip, net.hosts()))

    alive = [ip for ip, status in results if status]
    print(f"Alive hosts ({len(alive)}):")
    for ip in alive:
        print(ip)

# ---------------- DNS Brute Force ----------------
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "secure", "server", "vpn", "m", "blog"
]

def dns_brute_force(domain):
    print(f"Starting DNS brute force on {domain} ...")
    for sub in COMMON_SUBDOMAINS:
        try:
            full_domain = f"{sub}.{domain}"
            ip = socket.gethostbyname(full_domain)
            print(f"Found: {full_domain} -> {ip}")
        except socket.gaierror:
            pass

# ---------------- Main Function ----------------
def main():
    parser = argparse.ArgumentParser(description="Kali Multi-tool CLI")

    # CLI arguments define kar rahe hain
    parser.add_argument("-u", "--url", help="Check if URL is harmful and show redirect chain")
    parser.add_argument("-ip", "--iplookup", help="Perform DNS and GeoIP lookup for IP address")
    parser.add_argument("-n", "--nmap", help="Run nmap scan on target (IP or domain)")
    parser.add_argument("-w", "--whois", help="Run whois lookup on target (IP or domain)")
    parser.add_argument("-t", "--traceroute", help="Run traceroute on target (IP or domain)")
    parser.add_argument("-ps", "--pingsweep", help="Ping sweep on subnet (CIDR notation)")
    parser.add_argument("-dbf", "--dnsbruteforce", help="DNS brute force on domain")

    args = parser.parse_args()

    # Arguments check karke function call karenge
    if args.url:
        print(f"Checking URL: {args.url}")
        if check_url_harmful(args.url):
            print("Warning: URL is harmful!")
        else:
            print("URL seems safe.")
        print("Redirect chain:")
        redirects = get_redirect_chain(args.url)
        for url in redirects:
            print(f"  -> {url}")

    elif args.iplookup:
        print(f"DNS lookup for IP: {args.iplookup}")
        hostname = dns_lookup(args.iplookup)
        print(f"Hostname: {hostname}")

        print("GeoIP info:")
        geo = geoip_lookup(args.iplookup)
        for k, v in geo.items():
            print(f"{k}: {v}")

    elif args.nmap:
        run_nmap(args.nmap)

    elif args.whois:
        run_whois(args.whois)

    elif args.traceroute:
        run_traceroute(args.traceroute)

    elif args.pingsweep:
        ping_sweep(args.pingsweep)

    elif args.dnsbruteforce:
        dns_brute_force(args.dnsbruteforce)

    else:
        print("Please provide a valid option! Use -h for help.")

if __name__ == "__main__":
    main()
