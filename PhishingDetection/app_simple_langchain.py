"""
Flask app with Simple LangChain integration - No complex dependencies
"""

import os
import json
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from datetime import datetime

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Import simple LangChain wrapper
from simple_langchain_wrapper import SimpleLangChainOrchestrator

# Import original components for fallback
from app import (
    extract_ai_features, HostScanner, SandboxScanner, clean_html,
    model_xgb, model_nlp, shap_explainer, FEATURE_NAMES,
    run_agentic_workflow
)

app = Flask(__name__)
CORS(app)

# Initialize simple LangChain orchestrator
simple_orchestrator = SimpleLangChainOrchestrator()

@app.route('/')
def index():
    """Serve the main UI"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    """Enhanced scan endpoint with Simple LangChain orchestration"""
    data = request.get_json()
    url = data.get('url', '').strip()
    context = data.get('context', None)  # Additional context for analysis
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Check if this is a trusted domain
    from urllib.parse import urlparse
    TRUSTED_DOMAINS = {
        'google.com', 'www.google.com', 'mail.google.com', 'accounts.google.com',
        'microsoft.com', 'www.microsoft.com', 'office.com', 'outlook.com',
        'github.com', 'www.github.com',
        'stackoverflow.com', 'www.stackoverflow.com',
        'python.org', 'www.python.org',
        'facebook.com', 'www.facebook.com',
        'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
        'linkedin.com', 'www.linkedin.com',
        'amazon.com', 'www.amazon.com',
        'apple.com', 'www.apple.com'
    }
    
    domain = urlparse(url).netloc.lower()
    is_trusted = domain in TRUSTED_DOMAINS or any(domain.endswith('.' + trusted) for trusted in TRUSTED_DOMAINS)
    
    if is_trusted:
        return jsonify({
            'url': url,
            'verdict': 'LEGITIMATE',
            'confidence': 100.0,
            'method': 'trusted_domain',
            'page_title': 'Trusted Domain',
            'host_info': {'domain': domain, 'ip_address': 'Protected'},
            'ai_analysis': {
                'stream1_features': {'verdict': 'LEGITIMATE', 'phishing_prob': 0.0, 'top_reasons': []},
                'stream2_content': {'verdict': 'LEGITIMATE', 'phishing_prob': 0.0, 'suspicious_keywords': []}
            },
            'explainability': {'model': 'Trusted Domain Override', 'top_reasons': []},
            'agentic': {
                'final': {'verdict': 'LEGITIMATE', 'confidence': 1.0},
                'explanations': {'llm_bullets': ['This is a trusted domain with established reputation'], 'threat_intel': {}, 'threat_verdict': 'LEGITIMATE'},
                'agents': {}
            }
        })
    
    try:
        # Use Simple LangChain orchestrator with fallback
        result = simple_orchestrator.analyze_with_fallback(url, context)
        
        # Debug logging
        print(f"🔍 DEBUG: Simple LangChain result keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
        
        if result['status'] != 'success':
            return jsonify({'error': result.get('error', 'Analysis failed')}), 500
        
        # Transform result to match expected UI format
        method_used = result.get('method', 'simple_langchain')
        
        if method_used == 'fallback_original_orchestrator':
            # Original orchestrator format
            analysis = result['analysis']
            final_result = analysis.get('final', {})
            ml_agent = analysis.get('agents', {}).get('ml_model', {}).get('payload', {})
            content_agent = analysis.get('agents', {}).get('content_nlp', {}).get('payload', {})
            
            report = {
                'url': url,
                'verdict': final_result.get('verdict', 'INDETERMINATE'),
                'confidence': float(final_result.get('confidence', 0.0) * 100),
                'method': 'original_orchestrator',
                'ai_analysis': {
                    'stream1_features': {
                        'verdict': ml_agent.get('verdict', 'INDETERMINATE'),
                        'phishing_prob': float(ml_agent.get('phishing_prob', 0.0) * 100),
                        'top_reasons': ml_agent.get('top_reasons', [])
                    },
                    'stream2_content': {
                        'verdict': content_agent.get('verdict', 'INDETERMINATE'),
                        'phishing_prob': float(content_agent.get('phishing_prob', 0.0) * 100),
                        'suspicious_keywords': content_agent.get('suspicious_keywords', [])
                    }
                },
                'agentic': {
                    'final': final_result,
                    'explanations': analysis.get('explanations', {}),
                    'agents': analysis.get('agents', {})
                }
            }
        else:
            # Simple LangChain format
            final_assessment = result.get('final_assessment', {})
            analyses = result.get('analyses', {})
            
            # Extract data from analyses
            ml_data = analyses.get('ml_prediction', {}).get('data', {})
            content_data = analyses.get('content_analysis', {}).get('data', {})
            llm_data = analyses.get('llm_reasoning', {}).get('data', {})
            threat_data = analyses.get('threat_intel', {}).get('data', {})
            
            report = {
                'url': url,
                'verdict': final_assessment.get('final_verdict', 'INDETERMINATE'),
                'confidence': float(final_assessment.get('confidence', 0.5) * 100),
                'method': 'simple_langchain',
                'ai_analysis': {
                    'stream1_features': {
                        'verdict': ml_data.get('verdict', 'INDETERMINATE'),
                        'phishing_prob': float(ml_data.get('phishing_prob', 0.5) * 100),
                        'top_reasons': ml_data.get('top_reasons', [])
                    },
                    'stream2_content': {
                        'verdict': content_data.get('verdict', 'INDETERMINATE'),
                        'phishing_prob': float(content_data.get('phishing_prob', 0.5) * 100),
                        'suspicious_keywords': content_data.get('suspicious_keywords', [])
                    }
                },
                'agentic': {
                    'final': {
                        'verdict': final_assessment.get('final_verdict', 'INDETERMINATE'),
                        'confidence': final_assessment.get('confidence', 0.5),
                        'reasons': final_assessment.get('key_reasons', [])
                    },
                    'explanations': {
                        'llm_bullets': llm_data.get('bullets', []),
                        'threat_intel': threat_data.get('sources', {}),
                        'threat_verdict': threat_data.get('verdict', 'UNKNOWN')
                    },
                    'agents': analyses
                }
            }
        
        # Add traditional scan data for UI compatibility
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        host_scanner = HostScanner(domain)
        sandbox_scanner = SandboxScanner(url)
        
        host_info = host_scanner.scan()
        sandbox_result = sandbox_scanner.scan()
        
        report.update({
            'page_title': sandbox_result.get('page_title', 'No Title'),
            'screenshot_path': 'sandbox/output/screenshot.png',  # Use relative path for UI
            'host_info': host_info,
            'explainability': {
                "model": "XGBoost + Simple LangChain Orchestration",
                "top_reasons": report['ai_analysis']['stream1_features']['top_reasons']
            }
        })
        
        return jsonify(report)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/scan/simple-langchain', methods=['POST'])
def scan_with_simple_langchain_only():
    """Pure Simple LangChain analysis endpoint"""
    data = request.get_json()
    url = data.get('url', '').strip()
    context = data.get('context', None)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        result = simple_orchestrator.analyze_url_with_llm_guidance(url, context)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Simple LangChain analysis failed: {str(e)}'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'simple_langchain_available': True,
        'openai_configured': bool(os.getenv("OPENAI_API_KEY"))
    })

@app.route('/sandbox/output/<filename>')
def serve_screenshot(filename):
    """Serve screenshots from sandbox output"""
    return send_from_directory('sandbox/output', filename)

if __name__ == '__main__':
    print("🚀 Starting Phishing Detection with Simple LangChain Integration")
    print("📊 Available endpoints:")
    print("   POST /scan - Enhanced analysis with Simple LangChain + fallback")
    print("   POST /scan/simple-langchain - Pure Simple LangChain analysis")
    print("   GET  /health - Health check")
    print(f"   OpenAI Configured: {bool(os.getenv('OPENAI_API_KEY'))}")
    print("   ✅ Python 3.12 Environment - No dependency conflicts!")
    print("   ✅ Simple LangChain - Works without complex imports!")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
