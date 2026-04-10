import sys
import os
import asyncio
import json
import socket
import base64
import requests
# Check if whois is installed, handle if missing
try:
    import whois
except ImportError:
    whois = None

import dns.resolver
from urllib.parse import urlparse
from crawl4ai import AsyncWebCrawler, CacheMode  # Added CacheMode
from playwright.async_api import async_playwright
import nest_asyncio

nest_asyncio.apply()

OUTPUT_DIR = "/app/output"

# --- 1. NETWORK INTELLIGENCE ---
def get_ip_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}

def gather_network_intel(url):
    print("--- Guest: Starting Passive Network Recon ---")
    domain = urlparse(url).netloc
    if not domain:
        domain = urlparse(f"http://{url}").netloc
        
    intel = {
        "domain": domain,
        "ip": None,
        "reverse_dns": "N/A",
        "geolocation": {},
        "whois": {},
        "dns_records": {"A": [], "MX": [], "NS": [], "TXT": []}
    }

    try:
        # IP & Geo
        try:
            ip = socket.gethostbyname(domain)
            intel["ip"] = ip
            intel["geolocation"] = get_ip_location(ip)
        except:
            print("--- Guest: DNS Resolution Failed ---")

        # DNS Records
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for r_type in ["A", "MX", "NS", "TXT"]:
            try:
                answers = resolver.resolve(domain, r_type)
                intel["dns_records"][r_type] = [r.to_text() for r in answers]
            except: continue

        # Whois
        if whois:
            try:
                w = whois.whois(domain)
                intel["whois"] = {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date),
                    "emails": w.emails
                }
            except: pass

    except Exception as e:
        print(f"--- Guest: Recon Error: {e} ---")

    return intel

# --- 2. SCREENSHOT FALLBACK (With Cleanup) ---
async def take_screenshot_fallback(url):
    """
    Standard Playwright browser to ensure we get a picture if the crawler fails.
    """
    print("--- Guest: Attempting Fallback Screenshot... ---")
    path = os.path.join(OUTPUT_DIR, "screenshot.png")
    
    # Clean up old screenshot first
    if os.path.exists(path):
        os.remove(path)

    try:
        async with async_playwright() as p:
            # --no-sandbox is critical for Docker stability
            browser = await p.chromium.launch(
                headless=True, 
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
            page = await context.new_page()
            
            try:
                # wait_until='domcontentloaded' is faster and less prone to timeout than 'networkidle'
                await page.goto(url, timeout=20000, wait_until="domcontentloaded")
                # wait a tiny bit for renders
                await page.wait_for_timeout(2000)
            except Exception as e:
                print(f"--- Guest: Page load warning: {e} (Attempting screenshot anyway) ---")
            
            await page.screenshot(path=path, full_page=False)
            await browser.close()
            
            if os.path.exists(path):
                print("--- Guest: Fallback Screenshot Saved Successfully! ---")
                return True
            else:
                return False
    except Exception as e:
        print(f"--- Guest: Fallback Screenshot Failed: {e} ---")
        return False

# --- 3. ACTIVE SCANNER ---
async def crawl_target(url):
    print(f"--- Guest: Starting Stealth Crawl for {url} ---")
    
    # FORCE BYPASS CACHE
    async with AsyncWebCrawler(verbose=True) as crawler:
        result = await crawler.arun(
            url=url,
            cache_mode=CacheMode.BYPASS,  # <--- CRITICAL: Forces fresh fetch
            magic=True,
            screenshot=True, 
            js_code="window.scrollTo(0, document.body.scrollHeight);"
        )

        if not result.success:
            print("--- Guest: Crawl Failed (Success=False) ---")
            return None, None, None

        return result.html, result.screenshot, result.markdown

# --- 4. MAIN ORCHESTRATOR ---
async def main(url):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # CLEANUP: Delete old files so we don't accidentally serve stale data
    for f in ["page.html", "content.md", "screenshot.png", "network_intel.json"]:
        p = os.path.join(OUTPUT_DIR, f)
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"--- Guest: Cleaned up old {f} ---")
            except: pass
    
    # Run Network Recon
    loop = asyncio.get_running_loop()
    network_task = loop.run_in_executor(None, gather_network_intel, url)
    crawl_task = crawl_target(url)
    
    network_data, crawl_result = await asyncio.gather(network_task, crawl_task)
    
    html_content, screenshot_data, markdown_text = crawl_result if crawl_result else (None, None, None)

    # SAVE RESULTS
    if html_content:
        with open(os.path.join(OUTPUT_DIR, "page.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
        print("--- Guest: page.html updated ---")
            
    if markdown_text:
        with open(os.path.join(OUTPUT_DIR, "content.md"), "w", encoding="utf-8") as f:
            f.write(markdown_text)
        print("--- Guest: content.md updated ---")

    # SCREENSHOT LOGIC
    screenshot_saved = False
    
    # Attempt 1: From Crawler
    if screenshot_data:
        try:
            with open(os.path.join(OUTPUT_DIR, "screenshot.png"), "wb") as f:
                f.write(base64.b64decode(screenshot_data))
            screenshot_saved = True
            print("--- Guest: Screenshot saved from Crawler ---")
        except: 
            pass
    
    # Attempt 2: Fallback
    if not screenshot_saved:
        await take_screenshot_fallback(url)
    
    with open(os.path.join(OUTPUT_DIR, "network_intel.json"), "w", encoding="utf-8") as f:
        json.dump(network_data, f, indent=4)

    print("--- Guest: Scan Complete. ---")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(main(sys.argv[1]))