from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import requests
from urllib.parse import urlparse

@dataclass
class AgentResult:
    name: str
    payload: Dict[str, Any]
    errors: List[str]

class PreprocessingAgent:
    name = "preprocessing"
    def run(self, url: str) -> AgentResult:
        normalized = (url or "").strip()
        if not normalized: return AgentResult(self.name, {}, ["URL required"])
        if not urlparse(normalized).scheme: normalized = f"https://{normalized}"
        return AgentResult(self.name, {"url": normalized}, [])

class UrlAnalysisAgent:
    name = "url_analysis"
    def run(self, url: str, feature_vector: Optional[List[int]]) -> AgentResult:
        risk_score = 0.0 # Default to safe
        if feature_vector:
            # -1 = Safe, 0 = Suspicious, 1 = Phishing
            # Calculate ratio of Phishing(1) features
            phishing_count = sum(1 for v in feature_vector if v == 1)
            suspicious_count = sum(1 for v in feature_vector if v == 0)
            
            # Simple weighted score
            total_score = (phishing_count * 1.0) + (suspicious_count * 0.5)
            # Normalize (assuming max ~10 bad features is high risk)
            risk_score = min(total_score / 5.0, 1.0)
            
        return AgentResult(self.name, {"risk_score": risk_score, "feature_vector": feature_vector}, [])

class HeaderMetadataAgent:
    name = "header_metadata"
    def run(self, host_info: Dict[str, Any]) -> AgentResult:
        # INTELLIGENT SCORING:
        # If we have valid SSL and an IP, this is likely legitimate infrastructure.
        risk_score = 0.5 # Default neutral
        
        ssl_valid = host_info.get('ssl', {}).get('valid', False)
        ip_found = host_info.get('ip') != 'Not Found'
        
        if ssl_valid and ip_found:
            risk_score = 0.1 # Very Low Risk (Legitimate)
        elif not ip_found:
            risk_score = 0.9 # High Risk (Dead link/suspicious)
            
        return AgentResult(self.name, {
            "risk_score": risk_score, 
            "host_data": host_info 
        }, [])

class ContentNlpAgent:
    name = "content_nlp"
    def run(self, clean_text: str, model) -> AgentResult:
        verdict, prob, keywords = "INDETERMINATE", 0.5, []
        
        # If text is very short/empty, high risk of evasion
        if not clean_text or len(clean_text) < 50:
             return AgentResult(self.name, {"verdict": "INDETERMINATE", "phishing_prob": 0.5, "suspicious_keywords": []}, [])

        if model:
            try:
                # prob is "Probability of Phishing"
                prob = float(model.predict_proba([clean_text])[0][1])
                verdict = "PHISHING" if prob > 0.6 else "LEGITIMATE"
                keywords = [k for k in ["urgent", "verify", "password", "suspend", "account"] if k in clean_text.lower()]
            except: pass
            
        return AgentResult(self.name, {"verdict": verdict, "phishing_prob": prob, "suspicious_keywords": keywords}, [])

class MlModelAgent:
    name = "ml_model"
    def run(self, feature_vector: Optional[List[int]], model, shap_explainer, feature_names) -> AgentResult:
        verdict, prob, reasons = "INDETERMINATE", 0.5, []
        if feature_vector and model:
            try:
                import numpy as np
                inp = np.array(feature_vector).reshape(1, -1)
                prob = float(model.predict_proba(inp)[0][1])
                verdict = "PHISHING" if prob > 0.5 else "LEGITIMATE"
                
                if shap_explainer:
                    vals = shap_explainer.shap_values(inp)
                    if isinstance(vals, list): vals = vals[1][0]
                    elif len(vals.shape) > 1: vals = vals[0]
                    
                    # Only show features driving the Phishing prediction (Positive SHAP values)
                    # OR if Legitimate, show what makes it safe (Negative values) - optional, here we focus on risk.
                    reasons = [{"feature": feature_names.get(i, f"F{i}"), "impact_score": float(v)} for i, v in enumerate(vals) if v > 0.1][:5]
            except Exception as e: return AgentResult(self.name, {}, [str(e)])
        return AgentResult(self.name, {"verdict": verdict, "phishing_prob": prob, "top_reasons": reasons}, [])

class ThreatIntelAgent:
    name = "threat_intel"
    def run(self, url: str, host_info: Dict) -> AgentResult:
        # Placeholder: If we have no external intel, assume low risk (Clean until proven guilty)
        # In a real app, you'd check VirusTotal API here.
        return AgentResult(self.name, {"verdict": "CLEAN", "risk_score": 0.1, "sources": {}}, [])

class RiskAggregationAgent:
    name = "risk_aggregation"
    def run(self, url_r, content_r, header_r, ml_r, threat_r) -> AgentResult:
        # ADJUSTED WEIGHTS:
        # ML Model (Stream 1) & NLP (Stream 2) are our strongest signals. 
        # Increase their weight.
        
        # url_r: Calculated from feature vector count
        # content_r: From NLP Model probability
        # header_r: From SSL/IP check
        # ml_r: From XGBoost probability
        # threat_r: 0.1 (Clean) or 0.9 (Malicious)
        
        score = (
            0.10 * url_r +      # Structure
            0.15 * content_r +  # Text
            0.10 * header_r +   # Infrastructure
            0.45 * ml_r +       # XGBoost (The Brain)
            0.20 * threat_r     # External Intel
        )
        
        return AgentResult(self.name, {"risk_score": score, "verdict": "PHISHING" if score > 0.5 else "LEGITIMATE"}, [])

class DecisionExplanationAgent:
    name = "decision_explanation"
    def run(self, url_res, header_res, ml_res) -> AgentResult:
        reasons = []
        if ml_res.payload.get("verdict") == "PHISHING": reasons.append("ML Model Detection")
        return AgentResult(self.name, {"reasons": reasons}, [])

class LlmReasoningAgent:
    name = "llm_reasoning"
    def run(self, url, summary) -> AgentResult:
        return AgentResult(self.name, {"bullets": ["Automated analysis complete."]}, [])