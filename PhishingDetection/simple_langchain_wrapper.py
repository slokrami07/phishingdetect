import os
import json
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from core_logic import SandboxScanner, extract_ai_features, model_xgb

class SimpleLangChainOrchestrator:
    def __init__(self):
        # Using GPT-4o-mini. If this fails, try "gpt-3.5-turbo"
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("⚠️ WARNING: OPENAI_API_KEY not found in environment!")
            self.llm = None
        else:
            self.llm = ChatOpenAI(temperature=0.2, model_name="gpt-4o-mini", api_key=api_key)

    def analyze_url(self, url):
        response = {"status": "success", "analysis": {}, "error": None}

        # 1. SCAN
        scanner = SandboxScanner(url)
        success = scanner.run_sandbox()
        if not success: return {"status": "error", "error": "Sandbox Scan Failed"}
        
        scan_results = scanner.get_results()
        
        # 2. ML
        features = extract_ai_features(url, None, scan_results['network_intel'])
        ml_prob = 0.0
        if model_xgb:
            try: ml_prob = float(model_xgb.predict_proba([features])[0][1])
            except: pass

        # 3. LLM
        markdown_content = scan_results.get('markdown', "")[:8000]
        
        # Check if LLM is active
        if self.llm:
            llm_verdict = self._get_llm_verdict(url, markdown_content, scan_results['network_intel'])
        else:
            llm_verdict = {"risk_score": 0.5, "explanation": "⚠️ OpenAI API Key missing. Skipping AI analysis."}

        # 4. RESULT
        final_score = (ml_prob * 0.4) + (llm_verdict.get('risk_score', 0.5) * 0.6)
        
        response['analysis'] = {
            "verdict": "PHISHING" if final_score > 0.6 else "LEGITIMATE",
            "confidence": round(final_score * 100, 1),
            "ml_score": ml_prob,
            "page_title": scan_results['page_title'],
            "network_intel": scan_results['network_intel'],
            "reasoning": llm_verdict.get('explanation', "No reasoning.")
        }
        return response

    def _get_llm_verdict(self, url, content, intel):
        template = """
        You are a Cyber Security Expert. Analyze this website.
        URL: {url}
        Registrar: {registrar}
        Content: {content}
        
        Provide JSON:
        {{
            "risk_score": 0.XX,
            "explanation": "Brief reasoning..."
        }}
        """
        prompt = PromptTemplate(input_variables=["url", "registrar", "content"], template=template)
        chain = prompt | self.llm
        
        try:
            geo = intel.get('geolocation', {})
            whois = intel.get('whois', {})
            result = chain.invoke({
                "url": url,
                "registrar": whois.get('registrar', "Unknown"),
                "content": content
            })
            clean_json = result.content.replace("```json", "").replace("```", "")
            return json.loads(clean_json)
            
        except Exception as e:
            # THIS PRINTS THE ERROR TO YOUR TERMINAL
            print(f"❌ LLM CRASHED: {e}") 
            return {"risk_score": 0.5, "explanation": f"LLM Error: {str(e)}"}