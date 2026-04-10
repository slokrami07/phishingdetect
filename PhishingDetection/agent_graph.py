import os
import re
import json
from datetime import datetime
from typing import TypedDict, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

# Import your Project Modules
from agent_tools import deep_dive_scan
from core_logic import extract_ai_features, model_xgb, is_whitelisted, normalize_url
from bs4 import BeautifulSoup

# --- CONFIGURATION ---

# LLM Priority: 1) vLLM (local, GPU) -> 2) Groq (cloud, free, no GPU) -> 3) Rule-based fallback
llm_vllm = ChatOpenAI(
    model="NousResearch/Meta-Llama-3.1-8B-Instruct",
    openai_api_key="EMPTY",
    openai_api_base="http://localhost:8000/v1",
    temperature=0,
    model_kwargs={"response_format": {"type": "json_object"}},
    request_timeout=10,   # Short timeout so we fail fast and fall back
)

llm_groq = None
try:
    groq_key = os.getenv("GROQ_API_KEY", "")
    if groq_key:
        # Groq supports the OpenAI API spec — use langchain_openai (already installed)
        # This avoids version conflicts with langchain-groq vs langchain 0.2.x
        llm_groq = ChatOpenAI(
            model="llama-3.1-8b-instant",
            openai_api_key=groq_key,
            openai_api_base="https://api.groq.com/openai/v1",
            temperature=0,
            request_timeout=30,
            # Groq supports JSON mode
            model_kwargs={"response_format": {"type": "json_object"}}
        )
        print("✅ Groq LLM: Ready as fallback (via OpenAI-compatible endpoint)")
except Exception as e:
    print(f"⚠️  Groq not available: {e}")

# --- STATE DEFINITION ---
class AgentState(TypedDict):
    url: str
    scan_data: Dict[str, Any]
    xgb_score: float
    has_login : bool
    final_verdict: str
    reasoning: str

# --- NODES (The Steps) ---

def intelligence_node(state: AgentState):
    """
    Step 1: The Investigator.
    Runs the Docker container to get HTML and Network Intel.
    """
    print(f" [NODE 1] Gathering Intelligence for: {state['url']}")
    
    # Invoke the tool directly
    scan_results = deep_dive_scan.invoke(state['url'])
    
    # Extract HTML content for login detection
    has_login_form = False
    html_content = scan_results.get('html', '')
    
    if html_content:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for password inputs
            if soup.find("input", {"type": "password"}):
                has_login_form = True
            # Check for visible "Login" buttons if no input found
            elif soup.find("button", string=re.compile(r"log\s?in|sign\s?in", re.I)):
                has_login_form = True
        except Exception as e:
            print(f" Failed to parse HTML for login detection: {e}")
    
    return {"scan_data": scan_results, "xgb_score": scan_results.get('xgb_score', 0.0), "has_login": has_login_form}

def analyst_node(state: AgentState):
    """
    Step 2: The Mathematician.
    Checks Whitelist first, then runs XGBoost.
    """
    url = normalize_url(state['url'])
    print(f"📊 [NODE 2] Analyzing: {url}")
    
    # --- CHECK 1: WHITELIST (Instant Pass) ---
    if is_whitelisted(url):
        print("🛡️ Domain is in Top 50 Whitelist. Fast-tracking.")
        # We return a very low score so the Jury knows it's safe
        return {
            "xgb_score": 0.01, 
            "reasoning": "This is a verified major domain (Google/Amazon/etc)."
        }

    # --- CHECK 2: XGBOOST ---
    data = state['scan_data']
    
    # Reconstruct BeautifulSoup object
    raw_html = data.get('raw_html', "")
    soup = BeautifulSoup(raw_html, 'html.parser') if raw_html else None
    network_intel = data.get('network_intel', {})
    
    try:
        # Extract features using the NEW logic (hyphens, subdomains, etc.)
        features = extract_ai_features(url, soup, network_intel)
        
        if model_xgb:
            # Wrap in float() to prevent JSON serialization errors
            prob = float(model_xgb.predict_proba([features])[0][1]) 
        else:
            prob = 0.5 
            print("⚠️ XGBoost model not loaded, using fallback.")
            
    except Exception as e:
        print(f"❌ Feature Extraction Error: {e}")
        prob = 0.5

    print(f"📈 XGBoost Probability: {prob:.4f}")
    return {"xgb_score": prob}

def _rule_based_verdict(score: float, has_login: bool, domain_age_years) -> dict:
    """Fallback verdict when no LLM is available — pure rule-based logic."""
    if score < 0.1:
        return {"verdict": "SAFE", "reasoning": "Very low ML risk score. Domain appears safe."}
    elif score > 0.7:
        return {"verdict": "PHISHING", "reasoning": f"High ML risk score ({score:.2f}). Multiple phishing indicators detected in URL structure."}
    elif score > 0.4 and has_login:
        return {"verdict": "SUSPICIOUS", "reasoning": f"Moderate ML risk ({score:.2f}) combined with a login form. Treat with caution."}
    elif domain_age_years != "Unknown" and isinstance(domain_age_years, (int, float)) and domain_age_years > 10:
        return {"verdict": "SAFE", "reasoning": f"Domain is {domain_age_years} years old — established site."}
    else:
        return {"verdict": "SUSPICIOUS", "reasoning": f"ML score {score:.2f} is in the uncertain range. Manual review recommended."}


def judge_node(state: AgentState):
    """
    Step 3: The Jury (Llama 3 via vLLM or Groq, with rule-based fallback).
    LLM priority: vLLM (local) -> Groq (cloud) -> Rule-based
    """
    print(" [NODE 3] Judge is deliberating...")
    
    score = state['xgb_score']
    markdown = state['scan_data'].get('markdown', 'No content captured')[:5000]
    intel = state['scan_data'].get('network_intel', {}).get('whois', {})
    has_login = state.get('has_login', False)
    has_login_str = "YES" if has_login else "NO"
    
    # Extract Form Actions from HTML for semantic analysis
    raw_html = state['scan_data'].get('raw_html', "")
    soup = BeautifulSoup(raw_html, 'html.parser') if raw_html else None
    form_actions = []
    if soup:
        for form in soup.find_all('form'):
            action = form.get('action', '').strip()
            if action: form_actions.append(action)
    form_actions_str = ", ".join(form_actions) if form_actions else "None detected"
    
    # Extract creation date safely
    creation_date = str(intel.get('creation_date', 'Unknown'))
    
    # Calculate domain age using current real year (FIXED: was hardcoded 2025)
    domain_age_years = "Unknown"
    if creation_date != 'Unknown':
        try:
            year_match = re.search(r'(\d{4})', creation_date)
            if year_match:
                year = int(year_match.group(1))
                current_year = datetime.now().year
                domain_age_years = current_year - year
        except:
            domain_age_years = "Unknown"
    
    prompt = f"""
    You are PhishGuard AI, a sophisticated cybersecurity analyst. 
    Analyze this website for phishing threats.
    
    TARGET URL: {state['url']}
    
    TECHNICAL EVIDENCE:
    1. Machine Learning Risk Score: {score:.2f} / 1.0 
       (High Risk > 0.7 | Low Risk < 0.3)
       
    2. Domain Age: {domain_age_years} years (Created: {creation_date})
    
    3. Sensitive Input Detected (Login/Password): {has_login_str}
       Detected Form Actions (Where data is sent): {form_actions_str}
       
    4. Content Snippet:
       {markdown[:1500]}
    
    ---------------------------------------------------------
    DECISION LOGIC (Follow Strict Priority):
    1. WHITELIST RULE: IF Risk Score < 0.1, Verdict is SAFE.
    2. BRAND IMPERSONATION RULE: IF content mentions major brands BUT URL domain doesn't match -> PHISHING.
    3. STARTUP RULE: New domain + Login form + no clear business identity -> SUSPICIOUS/PHISHING.
    4. LEGACY RULE: Domain Age > 10 years -> SAFE (unless clearly hacked).
    ---------------------------------------------------------
    
    OUTPUT JSON ONLY:
    {{"verdict": "SAFE" or "PHISHING" or "SUSPICIOUS", "confidence": "Low/Medium/High", "reasoning": "Concise explanation."}}
    """
    
    # --- ATTEMPT 1: vLLM (local) ---
    try:
        print(" [NODE 3] Trying vLLM (localhost:8000)...")
        response = llm_vllm.invoke([HumanMessage(content=prompt)])
        decision = json.loads(response.content)
        print(" [NODE 3] vLLM responded successfully.")
        return {
            "final_verdict": decision.get("verdict", "UNKNOWN"),
            "reasoning": decision.get("reasoning", "Analysis complete.")
        }
    except Exception as e:
        print(f" [NODE 3] vLLM unavailable: {e}. Trying Groq...")
    
    # --- ATTEMPT 2: Groq (cloud, free, no GPU) ---
    if llm_groq:
        try:
            print(" [NODE 3] Trying Groq API (api.groq.com)...")
            groq_response = llm_groq.invoke([HumanMessage(content=prompt)])
            raw = groq_response.content.strip()
            print(f" [NODE 3] Groq raw response: {raw[:200]}")
            # JSON mode is enabled — parse directly, with regex fallback
            try:
                decision = json.loads(raw)
            except json.JSONDecodeError:
                json_match = re.search(r'\{.*\}', raw, re.DOTALL)
                decision = json.loads(json_match.group()) if json_match else {}
            print(" [NODE 3] Groq responded successfully.")
            return {
                "final_verdict": decision.get("verdict", "SUSPICIOUS"),
                "reasoning": decision.get("reasoning", "Analysis complete (via Groq).")
            }
        except Exception as e:
            print(f" [NODE 3] Groq FAILED: {type(e).__name__}: {e}")
    
    # --- ATTEMPT 3: Rule-based fallback (always works) ---
    print(" [NODE 3] Using rule-based fallback verdict.")
    decision = _rule_based_verdict(score, has_login, domain_age_years)
    decision["reasoning"] += " (Note: LLM unavailable — verdict based on ML score only.)"
    return {
        "final_verdict": decision["verdict"],
        "reasoning": decision["reasoning"]
    }

# --- GRAPH CONSTRUCTION ---

workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("gather_intel", intelligence_node)
workflow.add_node("analyze_risk", analyst_node)
workflow.add_node("judge", judge_node)

# Set Entry Point
workflow.set_entry_point("gather_intel")

# Define Edges (Linear flow: Intel -> Analyze -> Judge -> End)
workflow.add_edge("gather_intel", "analyze_risk")
workflow.add_edge("analyze_risk", "judge")
workflow.add_edge("judge", END)

# Compile
app_graph = workflow.compile()