import csv
import sys
import subprocess
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import re
import socket
import tldextract
import time
import requests
import ssl

# List of top legitimate websites to create a high-quality modern dataset
TOP_LEGITIMATE_SITES = [
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://www.twitter.com", "https://www.instagram.com", "https://www.wikipedia.org",
    "https://www.reddit.com", "https://www.amazon.com", "https://www.yahoo.com",
    "https://www.netflix.com", "https://www.linkedin.com", "https://www.microsoft.com",
    "https://www.apple.com", "https://www.github.com", "https://www.stackoverflow.com",
    "https://www.nytimes.com", "https://www.bbc.com", "https://www.cnn.com",
    "https://www.paypal.com", "https://www.ebay.com"
]

FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report", "Result"
]


def run_sandbox(url):
    """Runs the sandbox for a given URL and returns the path to the HTML file."""
    orchestrator_script = 'host_orchestrator.py'
    sandbox_dir = 'sandbox'
    html_path = os.path.join(sandbox_dir, 'output', 'page.html')

    output_dir = os.path.join(sandbox_dir, 'output')
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    try:
        command = [sys.executable, orchestrator_script, url]
        subprocess.run(command, check=True, text=True, cwd=sandbox_dir, capture_output=True, encoding='utf-8')
        return html_path if os.path.exists(html_path) else None
    except Exception as e:
        print(f"❌ Sandbox failed for {url}. Error: {e}")
        return None


def extract_features(url, soup):
    """Extracts the 30 features from the URL and its HTML content."""
    features = [1] * 30
    domain = urlparse(url).netloc
    main_domain_info = tldextract.extract(url)

    # --- Implement the full 30-feature logic ---
    try:
        ip_address = socket.gethostbyname(domain)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): features[0] = -1
    except:
        pass

    if 54 <= len(url) <= 75:
        features[1] = 0
    elif len(url) > 75:
        features[1] = -1

    if any(s in url for s in ["bit.ly", "goo.gl"]): features[2] = -1
    if "@" in url: features[3] = -1
    if url.rfind("//") > 7: features[4] = -1
    if "-" in domain: features[5] = -1

    dots = domain.count('.')
    if 'www.' in domain: dots -= 1
    if dots == 2:
        features[6] = 0
    elif dots > 2:
        features[6] = -1

    tls_info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                tls_info['issuer_org'] = issuer.get('organizationName', 'N/A')
    except:
        pass

    trusted_issuers = ["Google Trust Services", "Let's Encrypt", "Cloudflare", "Amazon", "Sectigo", "GoDaddy",
                       "DigiCert", "Microsoft", "GeoTrust"]
    issuer_org = tls_info.get('issuer_org', '')
    is_trusted_issuer = any(
        trusted in issuer_org for trusted in trusted_issuers) if issuer_org and issuer_org != 'N/A' else False
    if url.startswith("https"):
        features[7] = 1 if is_trusted_issuer else 0
    else:
        features[7] = -1

    if urlparse(url).port: features[10] = -1
    if "https" in domain: features[11] = -1

    if soup:
        if not (soup.find("link", rel=re.compile(r'icon', re.I))): features[9] = -1

        total_anchors = len(soup.find_all('a'))
        ext_anchors = 0
        for a in soup.find_all('a'):
            href = a.get('href')
            if href:
                link_domain_info = tldextract.extract(href)
                if link_domain_info.registered_domain and link_domain_info.registered_domain != main_domain_info.registered_domain:
                    ext_anchors += 1

        p_ext_anchors = (ext_anchors / total_anchors) * 100 if total_anchors > 0 else 0
        if 31 <= p_ext_anchors <= 67:
            features[13] = 0
        elif p_ext_anchors > 67:
            features[13] = -1

        sfh = 1
        for form in soup.find_all('form', action=True):
            action = form.get('action', '').lower()
            if action in ["", "about:blank"]: sfh = -1; break
            action_domain = tldextract.extract(form.get('action')).registered_domain
            if action_domain and action_domain != main_domain_info.registered_domain: sfh = 0
        features[15] = sfh

        if soup.find('form', action=re.compile(r'mailto:')): features[16] = -1
        if soup.find(onmouseover=re.compile(r'window\.status')): features[19] = -1
        if soup.find(oncontextmenu=re.compile(r'return false')): features[20] = -1
        if soup.find(onload=re.compile(r'alert\(')): features[21] = -1
        if soup.find_all('iframe'): features[22] = -1

    try:
        domain_info = whois.whois(domain)
        exp_date = domain_info.expiration_date
        if isinstance(exp_date, list): exp_date = exp_date[0]
        if (exp_date - datetime.now()).days <= 365: features[8] = -1
        cre_date = domain_info.creation_date
        if isinstance(cre_date, list): cre_date = cre_date[0]
        if (datetime.now() - cre_date).days < 180: features[23] = -1
        if not domain_info.domain_name: features[24] = -1
        whois_domains = [str(d).lower() for d in domain_info.domain_name] if isinstance(domain_info.domain_name,
                                                                                        list) else [
            str(domain_info.domain_name).lower()]
        if main_domain_info.registered_domain not in "".join(whois_domains): features[17] = -1
    except:
        features[8], features[23], features[24], features[17] = -1, -1, -1, -1

    features[12], features[14], features[18], features[25], features[26], features[28], features[
        29] = 1, 1, 1, 1, 1, 1, 1
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        if "did not match any documents" in response.text: features[27] = -1
    except:
        features[27] = -1

    return features


def create_dataset():
    """Scans a list of legitimate websites and saves their features to a CSV file."""
    output_csv_path = 'legitimate_sites_dataset.csv'

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(FEATURE_NAMES)  # Write header

        for url in TOP_LEGITIMATE_SITES:
            print(f"\nScanning: {url}")
            html_path = run_sandbox(url)

            if html_path:
                try:
                    with open(html_path, 'r', encoding='utf-8') as f:
                        soup = BeautifulSoup(f.read(), 'lxml')

                    features = extract_features(url, soup)
                    features.append(-1)  # Add the result: -1 for legitimate
                    writer.writerow(features)
                    print(f"✅ Successfully processed and saved features for {url}")
                except Exception as e:
                    print(f"❌ Error processing {url} after scan. Error: {e}")
            else:
                print(f"❌ Skipped {url} due to sandbox failure.")

            time.sleep(2)  # Add a small delay

    print(f"\n\nNew dataset created successfully at: {output_csv_path}")


if __name__ == "__main__":
    # Make sure we're in the main project directory
    if not os.path.exists('sandbox'):
        print("❌ Error: This script must be run from the main 'PhishingDetection' project directory.")
        sys.exit(1)

    # Need to import shutil for this script, make sure it's available
    import shutil

    create_dataset()

