import os
import sys
import json
import joblib
import xgboost as xgb
import tldextract
import re
import subprocess
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import requests

# --- CONFIGURATION ---
XGB_MODEL_PATH = 'phishing_model_v2.xgb'
NLP_MODEL_PATH = 'nlp_model_v1.pkl'

# --- WHITELIST (The "Silver Bullet") ---
# Top 50 domains to instantly trust (prevents False Positives on big tech)
WHITELIST = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "yahoo.com",
    "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com", "netflix.com",
    "microsoft.com", "apple.com", "whatsapp.com", "reddit.com", "bing.com",
    "office.com", "live.com", "twitch.tv", "github.com", "stackoverflow.com",
    "adobe.com", "cnn.com", "nytimes.com", "bbc.co.uk", "paypal.com",
    "dropbox.com", "wordpress.org", "zoom.us", "salesforce.com", "craigslist.org"
}

print("⏳ Loading AI Models...")
model_xgb = None  # Will be set to XGBClassifier if model loads successfully

try:
    if os.path.exists(XGB_MODEL_PATH):
        model_xgb = xgb.XGBClassifier()
        model_xgb.load_model(XGB_MODEL_PATH)
        print("✅ XGBoost: Active")
    else:
        print(f"⚠️ Warning: XGBoost model not found at {XGB_MODEL_PATH}")
except Exception as e:
    print(f"❌ XGBoost Error: {e}")

# --- HELPER FUNCTIONS ---
def normalize_url(url):
    if not url: return ""
    if not url.startswith(('http://', 'https://')): return 'https://' + url
    return url

def is_whitelisted(url):
    """Checks if the domain is in our trusted list."""
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    return domain in WHITELIST

# --- SANDBOX SCANNER (Unchanged) ---
class SandboxScanner:
    def __init__(self, url):
        self.url = normalize_url(url)
        self.output_dir = os.path.join(os.getcwd(), 'sandbox', 'output')

    def run_sandbox(self):
        script_path = os.path.join('sandbox', 'host_orchestrator.py')
        print(f"🐳 Sandbox: Dispatching Stealth Agent for {self.url}...")
        try:
            env = os.environ.copy()
            subprocess.run(
                [sys.executable, script_path, self.url], 
                check=True, capture_output=True, text=True, env=env, timeout=180
            )
            return True
        except Exception as e:
            print(f"❌ Sandbox Error: {e}")
            return False

    def get_results(self):
        results = {'success': False, 'raw_html': "", 'markdown': "", 'network_intel': {}}
        
        # Read Intel
        try:
            with open(os.path.join(self.output_dir, 'network_intel.json'), 'r', encoding='utf-8') as f:
                results['network_intel'] = json.load(f)
        except: pass
        
        # Read HTML
        try:
            with open(os.path.join(self.output_dir, 'page.html'), 'r', encoding='utf-8') as f:
                results['raw_html'] = f.read()
                results['success'] = True
        except: pass
        
        # Read Markdown
        try:
            with open(os.path.join(self.output_dir, 'content.md'), 'r', encoding='utf-8') as f:
                results['markdown'] = f.read()
        except: pass
            
        return results

# --- ENHANCED FEATURE EXTRACTOR ---
def extract_ai_features(url, soup, network_intel):
    """
    Extracts 30 features.
    Rules: -1 = Legitimate, 1 = Phishing, 0 = Suspicious
    """
    # Initialize with -1 (Benefit of the doubt)
    features = [-1] * 30 
    
    url = normalize_url(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    
    # 1. IP Address in URL (Strong Phishing Indicator)
    # Regex for IPv4
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        features[0] = 1 

    # 2. URL Length (Phishing sites are often very long)
    if len(url) < 54: features[1] = -1
    elif 54 <= len(url) <= 75: features[1] = 0
    else: features[1] = 1
    
    # 3. Shortening Service (bit.ly, etc)
    shorteners = ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "is.gd", "t.co"]
    if any(s in url for s in shorteners):
        features[2] = 1

    # 4. @ Symbol (Browsers ignore text before @)
    if "@" in url: 
        features[3] = 1
        
    # 5. Double Slash Redirect (// in path)
    # Legit: https://google.com (// is at pos 6 or 7)
    # Phishing: http://site.com//login
    if url.rfind('//') > 7:
        features[4] = 1

    # 6. Prefix/Suffix in Domain (e.g. google-login.com)
    if '-' in domain:
        features[5] = 1 # Legit sites rarely use hyphens in the main domain

    # 7. Subdomain Count (Many dots = Suspicious)
    dots = subdomain.count('.')
    if dots == 0: features[6] = -1  # google.com
    elif dots == 1: features[6] = 0 # drive.google.com
    else: features[6] = 1           # secure.account.login.google.com
    
    # 8. SSL Final State (From Scanner)
    if not url.startswith("https"):
        features[7] = 1
    
    # 9. Domain Registration Length (Whois)
    try:
        whois = network_intel.get('whois', {})
        creation = whois.get('creation_date')
        if creation:
             # Parse basic date (simplified)
             # Logic: If created < 1 year ago -> Phishing
             if "2025" in str(creation) or "2026" in str(creation):
                 features[8] = 1
             else:
                 features[8] = -1 # Older domains are safer
    except: pass
    
    # 10. HTTPS Token in Domain (http://https-secure.com)
    if 'https' in domain or 'https' in subdomain:
        features[11] = 1

    # 13. Anchor URL (Links in <a> tags) / Link Integrity
    if soup:
        unsafe_links: int = 0
        total_links: int = 0
        for a in soup.find_all('a', href=True):
            total_links += 1
            link = a['href']
            # Dead links or external domain links
            if link.startswith("#") or "javascript:" in link.lower() or (link.startswith("http") and domain not in link):
                unsafe_links += 1
        
        if total_links > 0:
            percentage = float(unsafe_links) / float(total_links)
            if percentage < 0.31: features[13] = -1
            elif 0.31 <= percentage <= 0.67: features[13] = 0
            else: features[13] = 1

    # --- PHASE 4.B: DOM VECTORS ---
    if soup:
        # 14. Form Actions (Third-party or empty destinations)
        forms = soup.find_all('form')
        if forms:
            malicious_form = False
            for form in forms:
                action = form.get('action', '').strip().lower()
                if not action or action.startswith("#") or action.startswith("javascript:"):
                    malicious_form = True # Empty/dead action
                elif action.startswith("http") and domain not in action:
                    malicious_form = True # Sends data off-site
            features[14] = 1 if malicious_form else -1
        else:
            features[14] = -1

        # 15. Hidden Elements (Stealth inputs, invisible iframes)
        hidden_count: int = 0
        hidden_count += len(soup.find_all('input', type='hidden'))
        hidden_count += len(soup.find_all(style=lambda value: value and ('display:none' in value.replace(' ', '') or 'visibility:hidden' in value.replace(' ', ''))))
        
        if hidden_count > 2: # More than a couple hidden elements is suspicious
            features[15] = 1
        else:
            features[15] = -1

        # 16. External Asset Ratio (CSS/JS/Images)
        total_assets: int = 0
        ext_assets: int = 0
        for tag, attr in [('link', 'href'), ('script', 'src'), ('img', 'src')]:
            for node in soup.find_all(tag, **{attr: True}):
                total_assets += 1
                link = node[attr]
                if link.startswith("http") and domain not in link:
                    ext_assets += 1
        
        if total_assets > 0:
            asset_ratio = float(ext_assets) / float(total_assets)
            features[16] = 1 if asset_ratio > 0.5 else -1 # If >50% assets are loaded externally
        else:
            features[16] = -1

    # --- PHASE 4.C: NETWORK VECTORS ---
    # 17. Redirect Hops 
    try:
        # Fast HEAD request to count redirects without downloading body
        resp = requests.head(url, allow_redirects=True, timeout=3)
        hops = len(resp.history)
        if hops >= 2: features[17] = 1
        elif hops == 1: features[17] = 0
        else: features[17] = -1
    except:
        features[17] = 1 # Network timeout/failure is suspicious

    # 24. DNS Record (Empty = Phishing)
    if not network_intel.get('ip'):
        features[24] = 1
        
    return features