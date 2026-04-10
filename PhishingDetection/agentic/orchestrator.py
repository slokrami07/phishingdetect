from typing import Any, Dict
from .agents import (
    PreprocessingAgent, UrlAnalysisAgent, HeaderMetadataAgent, ContentNlpAgent,
    MlModelAgent, ThreatIntelAgent, RiskAggregationAgent, DecisionExplanationAgent, LlmReasoningAgent
)

def run_agentic_workflow(url: str, *, host_info, feature_vector, clean_text, nlp_model, ml_model, shap_explainer, feature_names) -> Dict[str, Any]:
    
    # 1. Preprocessing
    pre = PreprocessingAgent().run(url)
    target_url = pre.payload["url"]

    # 2. Parallel Analysis
    url_agent = UrlAnalysisAgent().run(target_url, feature_vector)
    header_agent = HeaderMetadataAgent().run(host_info)
    content_agent = ContentNlpAgent().run(clean_text, nlp_model)
    ml_agent = MlModelAgent().run(feature_vector, ml_model, shap_explainer, feature_names)
    threat_agent = ThreatIntelAgent().run(target_url, host_info)

    # 3. Aggregation
    agg_agent = RiskAggregationAgent().run(
        url_agent.payload.get("risk_score", 0),
        content_agent.payload.get("phishing_prob", 0),
        header_agent.payload.get("risk_score", 0),
        ml_agent.payload.get("phishing_prob", 0),
        threat_agent.payload.get("risk_score", 0)
    )

    # 4. Explanation
    expl_agent = DecisionExplanationAgent().run(url_agent, header_agent, ml_agent)
    llm_agent = LlmReasoningAgent().run(target_url, {"ml_risk": ml_agent.payload.get("phishing_prob")})

    # --- CRITICAL FIX: Convert AgentResult objects to Dictionaries ---
    return {
        "final": agg_agent.payload,
        "agents": {
            "ml_model": {"payload": ml_agent.payload, "errors": ml_agent.errors},
            "content_nlp": {"payload": content_agent.payload, "errors": content_agent.errors},
            "threat_intel": {"payload": threat_agent.payload, "errors": threat_agent.errors},
            "header_metadata": {"payload": header_agent.payload, "errors": header_agent.errors}
        },
        "explanations": {
            "llm_bullets": llm_agent.payload.get("bullets", []),
            "reasons": expl_agent.payload.get("reasons", []),
            "threat_intel": threat_agent.payload.get("sources", {}),
            "threat_verdict": threat_agent.payload.get("verdict", "UNKNOWN")
        }
    }