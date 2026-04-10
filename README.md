# 🛡️ PhishGuard: Intelligent Phishing Detection System

PhishGuard is an advanced, multi-layered phishing detection platform combining **Threat Intelligence**, **Machine Learning (XGBoost)**, and **LLM-driven Agentic Workflow (LangChain)** to accurately classify URLs in real-time.

## 🌟 Key Features

1. **Multi-Stage Scanning Pipeline**
   - **Fast-Track Whitelist**: Bypasses deep scanning for known safe domains (e.g. `google.com`, `github.com`).
   - **Local Threat Intel DB**: Instant classification for known bad actors.
   - **Deep AI Agent Analysis**: LangChain-powered state machine that deep-dives into suspicious and unknown URLs.

2. **Hybrid Intelligence**
   - **XGBoost ML Models**: High-performance URL structure and heuristic prediction.
   - **Groq LLaMA / OpenAI**: Provides human-readable forensic reasoning and edge-case intelligence.

3. **Robust Backend & API**
   - Built on **Flask** with `Flask-Limiter` for rate tracking.
   - Provides REST endpoints (`/api/check`, `/api/deep-scan`, `/api/batch-scan`) intended for seamless browser extension integration.
   - Collects background network intelligence (`DNS`, `WHOIS`, `Geolocation`).

4. **Security & Performance**
   - **Playwright** integration for safe sandboxing and automatic threat screenshots.
   - Threadpool-based parallel checking for batch requests (up to 10 URLs at a time).
   - SQLite integration for tracking scan history locally.

## 🚀 Quick Start

### 1. Requirements
- Python 3.9+

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/slokrami07/phishingdetect.git
cd phishingdetect/PhishingDetection

# Create Virtual Environment (Optional but recommended)
python -m venv venv
source venv/bin/activate  # Or `venv\Scripts\activate` on Windows

# Install Dependencies
pip install -r requirements.txt

# Download Playwright Chromium Browsers
playwright install chromium
```

### 3. Environment Variables
Copy the template file to create your local environment setting:
```bash
cp .env.example .env
```
Ensure you provide a valid `GROQ_API_KEY` (Free to get a key online) to enable LLM-driven intelligence. 

### 4. Run the Server
```bash
python app.py
```
The Server & Dashboard will start on `http://127.0.0.1:5000/`.

## 📡 Essential API Endpoints

- `POST /api/check`: Fast triage URL scan. (Expects JSON: `{"url": "example.com"}`)
- `POST /api/deep-scan`: Detailed AI analysis bridging Threat Intel with ML.
- `POST /api/batch-scan`: Quickly process an array of URLs.
- `GET /api/history`: Retrieve the last 100 scan logs from the database.
- `GET /api/status`: System Dashboard and real-time processing queues.

## 🛠️ Stack Overview
- **Core Framework**: Flask, Python (Pandas, Numpy)
- **Machine Learning**: XGBoost, Scikit-Learn
- **Orchestration**: LangChain, LangChain-Groq / OpenAI
- **Network Intel**: python-whois, dnspython, sockets
- **Sandboxing**: Playwright API
