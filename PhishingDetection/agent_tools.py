from langchain_core.tools import tool
from core_logic import SandboxScanner
import json

@tool
def deep_dive_scan(url: str):
    """
    Triggers the Docker Sandbox to securely crawl the URL.
    Returns: HTML content (markdown), Network Intel (Whois/DNS), and success status.
    Use this tool to gather evidence before making a verdict.
    """
    print(f"🕵️  [TOOL] Launching SandboxScanner for: {url}")
    
    # 1. Initialize your existing class
    scanner = SandboxScanner(url)
    
    # 2. Run the Docker subprocess
    success = scanner.run_sandbox()
    
    # 3. Retrieve the artifacts (content.md, network_intel.json)
    results = scanner.get_results()
    
    # 4. Add a status flag for the Agent
    results["scan_status"] = "success" if success else "failed"
    
    # Trim content to prevent overflowing the LLM context window
    if results.get("markdown"):
        results["markdown"] = results["markdown"][:4000] 
        
    return results