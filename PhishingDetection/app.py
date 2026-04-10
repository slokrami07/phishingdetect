from ipaddress import ip_address
import os
import time
import warnings
import re
import json
from datetime import datetime
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Filter warnings
warnings.filterwarnings("ignore", category=UserWarning, message=".*Pydantic V1 functionality.*")

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# *** Load .env FIRST — before any project imports that read env vars at module level ***
# This ensures GROQ_API_KEY etc. are in os.environ when agent_graph.py initializes llm_groq
load_dotenv()

# (agent_graph, threat_intel, scan_history must come AFTER load_dotenv)
from agent_graph import app_graph
from threat_intel import phishing_db
from scan_history import scan_history


app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, resources={r"/*": {"origins": "*"}})

# --- RATE LIMITER ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://"
)

# --- HELPER: CLEAN MESSY DATA ---
def format_creation_date(raw_date):
    """
    Fixes the ugly '[datetime.datetime(...)]' string from the scanner
    """
    if not raw_date:
        return "Unknown"
    
    # If it's already a clean string, return it
    if isinstance(raw_date, str) and "datetime" not in raw_date:
        return raw_date
        
    # Use Regex to grab the first date (YYYY, M, D)
    match = re.search(r"datetime\.datetime\((\d{4}),\s*(\d{1,2}),\s*(\d{1,2})", str(raw_date))
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}" # Returns 1997-9-15
    
    return "Unknown"

# --- HELPER: LOG SCAN REQUEST ---
def log_scan_request(url, source, verdict, confidence=0.0, reasoning=''):
    """Log to both the legacy flat file and the new SQLite history."""
    # Legacy flat file (kept for backward compatibility with /api/status)
    log_path = os.path.join(os.getcwd(), 'scan_log.txt')
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"Scanning {url} ({source}): {verdict}\n")
    # New SQLite history
    scan_history.log_scan(url, verdict, confidence, source, reasoning)

@app.route('/')
def index():
    """Main Dashboard - Loads the latest scan data from disk if available"""
    
    # 1. Initialize default empty data
    scan_data = {
        "verdict": "Ready to Scan",
        "confidence": 0,
        "url": "",
        "host_info": {},
        "ai_analysis": None,
        "screenshot_path": None
    }

    # 2. Try to read the last scan's Network Intelligence
    intel_path = os.path.join(os.getcwd(), 'sandbox', 'output', 'network_intel.json')
    if os.path.exists(intel_path):
        try:
            with open(intel_path, 'r', encoding='utf-8') as f:
                network_intel = json.load(f)
                
                # Update our data object with the file content
                scan_data["host_info"] = {
                    "ip": network_intel.get('ip', 'N/A'),
                    "geolocation": network_intel.get('geolocation', {}),
                    "whois": network_intel.get('whois', {}),
                    "dns": network_intel.get('dns_records', {})
                }
                
                # Check for a screenshot
                screenshot_path = os.path.join(os.getcwd(), 'sandbox', 'output', 'screenshot.png')
                if os.path.exists(screenshot_path):
                    # Add a timestamp to force the browser to reload the image
                    scan_data["screenshot_path"] = f"sandbox_images/screenshot.png?t={int(time.time())}"
                    
        except Exception as e:
            print(f"Error loading previous scan data: {e}")

    # 3. Render the index page with this data
    return render_template('index.html', initial_data=scan_data)


@app.route('/api/check', methods=['POST'])
@limiter.limit("30 per minute")
def api_check():
    """
    Robust Analysis Pipeline:
    1. Threat Intel DB (Known Bad)
    2. Trusted Whitelist (Known Good)
    3. AI Agent (Unknown - Deep Analysis)
    """
    data = request.get_json()
    url = data.get('url')
    if not url: return jsonify({'error': 'URL Required'}), 400
    
    try:
        from urllib.parse import urlparse
        import socket
        
        # Parse Domain
        domain = urlparse(url).netloc
        if not domain: domain = urlparse(f"http://{url}").netloc
        if ":" in domain: domain = domain.split(":")[0]

        # ---------------------------------------------------------
        # STEP 1: PHISHING DATABASE CHECK (Highest Priority)
        # ---------------------------------------------------------
        if phishing_db.check_url(url):
            print(f" [DB] Found in phishing database: {url}")
            log_scan_request(url, "database_match", "malicious", 100.0,
                             "URL matches Threat Intelligence Database.")
            
            return jsonify({
                "url": url,
                "verdict": "malicious",
                "confidence": 100.0,
                "suggestDeepScan": False,
                "ai_analysis": {
                    "llm_reasoning": "FATAL: This URL matches a record in our Threat Intelligence Database. Access is strongly discouraged."
                },
                "host_info": {
                    "ip": "Blacklisted IP",
                    "domain": domain,
                    "geolocation": "Known Threat Source"
                }
            })

        # ---------------------------------------------------------
        # STEP 2: FAST WHITELIST CHECK (Optimization)
        # ---------------------------------------------------------
        TRUSTED_DOMAINS = {
            "google.com", "www.google.com", "gemini.google.com", "drive.google.com",
            "github.com", "www.github.com", "microsoft.com", "amazon.com",
            "facebook.com", "twitter.com", "linkedin.com", "youtube.com"
        }
        
        base_domain = ".".join(domain.split('.')[-2:])
        
        if domain in TRUSTED_DOMAINS or base_domain in TRUSTED_DOMAINS:
            print(f" [WHITELIST] Fast-track safe: {domain}")
            
            try: ip_addr = socket.gethostbyname(domain)
            except: ip_addr = "Trusted Cloud IP"

            log_scan_request(url, "whitelist", "safe", 5.0,
                             f"Domain '{domain}' is a verified trusted platform.")
            return jsonify({
                "url": url,
                "verdict": "safe",
                "confidence": 10.0,
                "suggestDeepScan": False,
                "ai_analysis": {
                    "llm_reasoning": f"The domain '{domain}' is a verified trusted platform. No analysis required."
                },
                "host_info": {
                    "ip": ip_addr,
                    "domain": domain,
                    "geolocation": "Verified Safe Location"
                }
            })

        # ---------------------------------------------------------
        # STEP 3: AI AGENT ANALYSIS (Deep Scan)
        # ---------------------------------------------------------
        print(f" [AI] Analyzing unknown URL: {url}")
        agent_result = app_graph.invoke({"url": url})
        
        final_verdict = agent_result.get("final_verdict", "UNKNOWN") 
        reasoning = agent_result.get("reasoning", "Analysis complete.")
        try: xgb_score = float(agent_result.get("xgb_score", 0.0))
        except: xgb_score = 0.5

        verdict_ext = "safe"
        if final_verdict == "PHISHING":
            verdict_ext = "malicious"
        elif final_verdict == "SAFE":
            verdict_ext = "safe"
        elif xgb_score > 0.6: 
            verdict_ext = "suspicious"
        
        try: ip_addr = socket.gethostbyname(domain)
        except: ip_addr = "Unresolved"

        log_scan_request(url, "ai_analysis", verdict_ext,
                         round(xgb_score * 100, 1), reasoning)

        return jsonify({
            "url": url,
            "verdict": verdict_ext,
            "confidence": round(xgb_score * 100, 1),
            "suggestDeepScan": xgb_score > 0.3 and xgb_score < 0.8,
            "ai_analysis": { "llm_reasoning": reasoning },
            "host_info": {
                "ip": ip_addr,
                "domain": domain,
                "geolocation": "Run Deep Scan for Details"
            }
        })

    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({
            "url": url, 
            "verdict": "suspicious", 
            "confidence": 0,
            "error": str(e),
            "ai_analysis": {"llm_reasoning": "Error during analysis."},
            "host_info": {}
        })

@app.route('/api/deep-scan', methods=['POST'])
@limiter.limit("5 per minute")
def api_deep_scan():
    """Extension API endpoint for deep scanning"""
    data = request.get_json()
    url = data.get('url')
    if not url: 
        return jsonify({'error': 'URL Required'}), 400
    
    try:
        # 1. First check phishing database
        if phishing_db.check_url(url):
            print(f" [DB] Deep scan: Found in phishing database: {url}")
            return jsonify({
                "url": url,
                "verdict": "malicious",
                "confidence": 100.0,
                "reasoning": "URL found in phishing threat intelligence database - confirmed malicious",
                "host_info": {
                    "ip": "Database Match",
                    "geolocation": {},
                    "whois": {},
                    "dns": {}
                },
                "suggestDeepScan": False,
                "source": "database"
            })
        
        print(f" [DB] Deep scan: Not found in database, running full AI analysis: {url}")
        
        # 2. If not in database, run full AI analysis
        agent_result = app_graph.invoke({"url": url})
        
        verdict = agent_result.get("final_verdict", "UNKNOWN")
        reasoning = agent_result.get("reasoning", "Analysis failed.")
        xgb_score = float(agent_result.get("xgb_score", 0.0))
        
        # Read network intelligence
        network_intel = {}
        intel_path = os.path.join(os.getcwd(), 'sandbox', 'output', 'network_intel.json')
        
        if os.path.exists(intel_path):
            try:
                with open(intel_path, 'r', encoding='utf-8') as f:
                    network_intel = json.load(f)
            except Exception as e:
                print(f" Failed to read network_intel.json: {e}")
        
        # Map verdict to extension format
        if verdict == "PHISHING":
            verdict_ext = "malicious"
        elif xgb_score > 0.5:
            verdict_ext = "suspicious"
        else:
            verdict_ext = "safe"
            
        return jsonify({
            "url": url,
            "verdict": verdict_ext,
            "confidence": round(xgb_score * 100, 1),
            "reasoning": reasoning,
            "host_info": {
                "ip": network_intel.get('ip', 'Not Found'),
                "geolocation": network_intel.get('geolocation', {}),
                "whois": network_intel.get('whois', {}),
                "dns": network_intel.get('dns_records', {})
            },
            "suggestDeepScan": False,
            "source": "ai_analysis"
        })
    except Exception as e:
        return jsonify({
            "url": url,
            "verdict": "suspicious", 
            "suggestDeepScan": False,
            "error": str(e),
            "source": "error"
        })

@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    """Extension API endpoint for user feedback"""
    data = request.get_json()
    url = data.get('url')
    action = data.get('action')
    
    if not url or not action:
        return jsonify({'error': 'URL and action required'}), 400
    
    # Here you could store feedback in database or log file
    print(f"📝 Feedback received: {action} for {url}")
    
    return jsonify({"success": True})

@app.route('/api/status')
def api_status():
    """Display current extension data and processing status as webpage"""
    try:
        # Read network intelligence if available
        network_intel = {}
        intel_path = os.path.join(os.getcwd(), 'sandbox', 'output', 'network_intel.json')
        
        if os.path.exists(intel_path):
            try:
                with open(intel_path, 'r', encoding='utf-8') as f:
                    network_intel = json.load(f)
            except Exception as e:
                print(f"⚠️ Failed to read network_intel.json: {e}")
        
        # Get recent scan results from logs or memory
        recent_scans = []
        log_path = os.path.join(os.getcwd(), 'scan_log.txt')
        
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()[-10:]  # Last 10 lines
                    for line in lines:
                        if 'Scanning' in line:
                            recent_scans.append(line.strip())
            except Exception as e:
                print(f"⚠️ Failed to read scan log: {e}")
        
        # Check if any scans are currently running
        running_scans = []
        if network_intel:
            running_scans.append(f"Network analysis for {network_intel.get('domain', 'Unknown domain')}")
        
        status_data = {
            "status": "active",
            "extension_connected": True,
            "current_processing": {
                "running_scans": running_scans,
                "queue_length": len(running_scans),
                "last_activity": datetime.now().isoformat()
            },
            "recent_extension_requests": recent_scans[-5:],  # Last 5 requests
            "network_intel_available": bool(network_intel),
            "current_network_data": {
                "domain": network_intel.get('domain', 'N/A'),
                "ip": network_intel.get('ip', 'N/A'),
                "geolocation": network_intel.get('geolocation', {}),
                "scan_status": "completed" if network_intel else "pending"
            },
            "api_endpoints": {
                "quick_check": "/api/check",
                "deep_scan": "/api/deep-scan", 
                "feedback": "/api/feedback",
                "status": "/api/status"
            }
        }
        
        return render_template('extension_status.html', data=status_data)
    except Exception as e:
        error_data = {
            "status": "error",
            "error": str(e),
            "extension_connected": False
        }
        return render_template('extension_status.html', data=error_data)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    if not url: return jsonify({'error': 'URL Required'}), 400
    
    print(f"🚀 PhishGuard: Scanning {url}...")
    
    try:
        # 1. RUN THE AGENT (The State Machine)
        agent_result = app_graph.invoke({"url": url})
        
        # 2. EXTRACT BASIC VERDICTS
        verdict = agent_result.get("final_verdict", "UNKNOWN")
        reasoning = agent_result.get("reasoning", "Analysis failed.")
        # Ensure float conversion happens here
        xgb_score = float(agent_result.get("xgb_score", 0.0))
        
        # 3. DIRECT DISK READ (The Fix)
        # We bypass the Agent State and read the file directly to guarantee data presence.
        network_intel = {}
        intel_path = os.path.join(os.getcwd(), 'sandbox', 'output', 'network_intel.json')
        
        if os.path.exists(intel_path):
            try:
                with open(intel_path, 'r', encoding='utf-8') as f:
                    network_intel = json.load(f)
                    print("✅ Successfully loaded network_intel.json from disk")
            except Exception as e:
                print(f"⚠️ Failed to read network_intel.json: {e}")
        else:
            print("⚠️ network_intel.json not found on disk")

        # 4. EXTRACT DATA SAFELY
        ip = network_intel.get('ip', 'Not Found')
        geo = network_intel.get('geolocation', {})
        if not geo: geo = {} # Ensure it's a dict even if None

        lat,lon = 0,0
        if 'loc' in geo:
            try:
                lat,lon = map(float, geo['loc'].split(','))
            except:
                pass
        elif 'latitude' in geo and 'longitude' in geo:
            lat,lon = geo['latitude'], geo['longitude']
        
        whois = network_intel.get('whois', {})
        if not whois: whois = {}
        
        dns = network_intel.get('dns_records', {})

        # Clean the date
        creation_date = format_creation_date(whois.get('creation_date'))

        # 5. BUILD RESPONSE
        response = {
            "verdict": verdict,
            "confidence": round(xgb_score * 100, 1), 
            "url": url,
            "page_title": "PhishGuard Scan Report",
            
            "ai_analysis": {
                "stream1_features": {
                    "verdict": "PHISHING" if xgb_score > 0.7 else "SAFE",
                    "phishing_prob": round(xgb_score * 100, 1),
                },
                "stream2_content": {
                    "verdict": verdict,
                    "phishing_prob": 95.0 if verdict == "PHISHING" else 10.0, 
                },
                "llm_reasoning": reasoning
            },
            
            "host_info": {
                "ip_address": ip,
                "geolocation": f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}",
                "isp": geo.get('isp', 'Unknown'),
                "asn": geo.get('as', 'Unknown'),
                "registrar": whois.get('registrar', 'Unknown'),
                "creation_date": creation_date,
                "emails": whois.get('emails', 'N/A'),
                "dns": dns
            },
            
            "screenshot_path": f"sandbox_images/screenshot.png?t={int(time.time())}"
        }
        
        # Log to SQLite history
        log_scan_request(url, "ai_analysis", verdict,
                         round(xgb_score * 100, 1), reasoning)
        
        return jsonify(response)

    except Exception as e:
        print(f"🔥 Critical API Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/sandbox_images/<path:filename>')
def serve_screenshot(filename):
    directory = os.path.join(os.getcwd(), 'sandbox', 'output')
    return send_from_directory(directory, filename)


# =============================================================================
# NEW ENDPOINTS ADDED IN UPGRADE
# =============================================================================

@app.route('/api/history', methods=['GET'])
def api_history():
    """Return the last 100 scan records from SQLite as JSON."""
    try:
        limit = int(request.args.get('limit', 100))
        limit = min(limit, 500)  # Cap at 500 for safety
        records = scan_history.get_recent(limit)
        return jsonify({"scans": records, "count": len(records)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Return verdict distribution counts and DB stats."""
    try:
        stats = scan_history.get_stats()
        db_info = phishing_db.get_db_stats()
        return jsonify({
            "verdict_counts": stats,
            "threat_db": db_info
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/batch-scan', methods=['POST'])
@limiter.limit("3 per minute")
def api_batch_scan():
    """
    Batch scan up to 10 URLs in parallel using ThreadPoolExecutor.
    Request body: {"urls": ["url1", "url2", ...]}
    """
    data = request.get_json()
    urls = data.get('urls', [])

    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    if len(urls) > 10:
        return jsonify({'error': 'Maximum 10 URLs per batch request'}), 400

    def scan_single(url):
        """Run a quick check on a single URL — reuses the same pipeline as /api/check."""
        try:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(url).netloc
            if not domain:
                domain = _urlparse(f"http://{url}").netloc
            if ':' in domain:
                domain = domain.split(':')[0]

            # DB check
            if phishing_db.check_url(url):
                log_scan_request(url, "database_match", "malicious", 100.0,
                                 "URL matches Threat Intelligence Database.")
                return {"url": url, "verdict": "malicious", "confidence": 100.0,
                        "source": "threat_database"}

            # Whitelist
            TRUSTED = {"google.com", "github.com", "microsoft.com", "amazon.com",
                       "facebook.com", "twitter.com", "linkedin.com", "youtube.com"}
            base = ".".join(domain.split('.')[-2:])
            if domain in TRUSTED or base in TRUSTED:
                log_scan_request(url, "whitelist", "safe", 5.0)
                return {"url": url, "verdict": "safe", "confidence": 5.0,
                        "source": "whitelist"}

            # AI Agent
            result = app_graph.invoke({"url": url})
            final = result.get("final_verdict", "UNKNOWN")
            score = float(result.get("xgb_score", 0.5))
            reasoning = result.get("reasoning", "")
            verdict = "malicious" if final == "PHISHING" else ("suspicious" if score > 0.6 else "safe")
            log_scan_request(url, "ai_analysis", verdict, round(score * 100, 1), reasoning)
            return {"url": url, "verdict": verdict, "confidence": round(score * 100, 1),
                    "reasoning": reasoning, "source": "ai_analysis"}
        except Exception as e:
            return {"url": url, "verdict": "error", "error": str(e)}

    print(f"📦 Batch scan: {len(urls)} URL(s) submitted")
    with ThreadPoolExecutor(max_workers=min(len(urls), 4)) as executor:
        results = list(executor.map(scan_single, urls))

    return jsonify({"results": results, "total": len(results)})


if __name__ == '__main__':
    app.run(debug=True, port=5000)