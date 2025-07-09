import requests
from collections import deque

# Insert your API keys here
API_KEYS = {
    "virustotal": "",
    "chaos": "",
    "bevigil": "",
    "alienvault": "",
    "urlscan": "",
    "shodan": "",
    "netlas": ""
}

def get_subdomains_virustotal(domain):
    subdomains = []
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": API_KEYS["virustotal"]}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("data", []):
                subdomains.append(item["id"])
    except Exception as e:
        print(f"[VT Error] {e}")
    return subdomains

def get_subdomains_chaos(domain):
    subdomains = []
    try:
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {"Authorization": API_KEYS["chaos"]}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            subdomains = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
    except Exception as e:
        print(f"[Chaos Error] {e}")
    return subdomains

def get_subdomains_bevigil(domain):
    subdomains = []
    try:
        url = f"https://osint.bevigil.com/api/{domain}/subdomains"
        headers = {"X-Access-Key": API_KEYS["bevigil"]}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            subdomains = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
    except Exception as e:
        print(f"[Bevigil Error] {e}")
    return subdomains

def get_subdomains_alienvault(domain):
    subdomains = []
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"X-OTX-API-KEY": API_KEYS["alienvault"]}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname")
                if hostname and domain in hostname:
                    subdomains.append(hostname)
    except Exception as e:
        print(f"[AlienVault Error] {e}")
    return subdomains

def get_subdomains_urlscan(domain):
    subdomains = []
    try:
        url = "https://urlscan.io/api/v1/search/"
        headers = {"API-Key": API_KEYS["urlscan"]}
        params = {"q": f"domain:{domain}"}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            for result in data.get("results", []):
                page_domain = result.get("page", {}).get("domain", "")
                if domain in page_domain:
                    subdomains.append(page_domain)
    except Exception as e:
        print(f"[URLScan Error] {e}")
    return subdomains

def get_subdomains_shodan(domain):
    subdomains = []
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={API_KEYS['shodan']}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for sub in data.get("subdomains", []):
                subdomains.append(f"{sub}.{domain}")
    except Exception as e:
        print(f"[Shodan Error] {e}")
    return subdomains

def get_subdomains_netlas(domain):
    subdomains = []
    try:
        url = f"https://app.netlas.io/api/domains/{domain}"
        headers = {"X-API-Key": API_KEYS["netlas"]}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("items", []):
                sub = item.get("name")
                if sub:
                    subdomains.append(sub)
    except Exception as e:
        print(f"[Netlas Error] {e}")
    return subdomains

# Combine all API-based subdomain discovery
def get_subdomains_from_apis(domain):
    all = set()
    for func in [
        get_subdomains_virustotal,
        get_subdomains_chaos,
        get_subdomains_bevigil,
        get_subdomains_alienvault,
        get_subdomains_urlscan,
        get_subdomains_shodan,
        get_subdomains_netlas
    ]:
        all.update(func(domain))
    return all

# Recursive enumeration logic
def recursive_enum(domain, max_depth=2):
    discovered = set()
    queue = deque([(domain, 0)])

    while queue:
        current_domain, level = queue.popleft()
        if level >= max_depth:
            continue

        try:
            subdomains = get_subdomains_from_apis(current_domain)
        except Exception as e:
            print(f"[!] Error querying {current_domain}: {e}")
            continue

        for subdomain in subdomains:
            if subdomain not in discovered:
                discovered.add(subdomain)
                queue.append((subdomain, level + 1))

    return discovered

def main():
    target = input("Enter domain: ").strip()
    max_depth = int(input("Enter recursion depth (e.g. 2): ").strip())

    all_subdomains = recursive_enum(target, max_depth)
    print(f"\n[+] Total Unique Subdomains (with nested levels): {len(all_subdomains)}")
    for sub in sorted(all_subdomains):
        print(sub)

if __name__ == "__main__":
    main()
