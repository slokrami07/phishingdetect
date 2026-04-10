# Use the official Playwright Python image (includes browsers)
FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

# Set working directory
WORKDIR /app

# Install system dependencies for stealth & networking
RUN apt-get update && apt-get install -y \
    iputils-ping \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements (if you have them) or install directly
# We install crawl4ai, nest_asyncio, and other networking tools
RUN pip install --no-cache-dir \
    crawl4ai \
    nest_asyncio \
    requests \
    python-whois \
    dnspython \
    beautifulsoup4

# Install Crawl4AI browser binaries
RUN python -m playwright install chromium

# Copy the scanner scripts
COPY guest_scanner.py .

# Create output directory
RUN mkdir -p output

# Default command (overridden by orchestrator)
CMD ["python", "guest_scanner.py", "https://google.com"]