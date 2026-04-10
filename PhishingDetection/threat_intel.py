import requests
import logging
import time
from apscheduler.schedulers.background import BackgroundScheduler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishingDB")

# We use the raw text files from the Phishing-Database repo
# These are the "Active" lists (high confidence)
PHISHING_DB_SOURCES = [
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
]

class PhishingDatabase:
    def __init__(self):
        self.blacklist = set()
        self.last_updated = 0
        self.refresh_database()

    def refresh_database(self):
        """Downloads and indexes the latest phishing lists from GitHub."""
        logger.info("🔄 [DB] Connecting to Phishing-Database (GitHub)...")
        
        total_added = 0
        for source in PHISHING_DB_SOURCES:
            try:
                response = requests.get(source, timeout=15)
                if response.status_code == 200:
                    lines = response.text.splitlines()
                    for line in lines:
                        clean_line = line.strip()
                        # Ignore comments and empty lines
                        if clean_line and not clean_line.startswith("#"):
                            self.blacklist.add(clean_line)
                    total_added += len(lines)
                    logger.info(f"✅ [DB] Loaded {len(lines)} entries from {source.split('/')[-1]}")
                else:
                    logger.warning(f"⚠️ [DB] Failed to download {source} (Status: {response.status_code})")
            except Exception as e:
                logger.error(f"❌ [DB] Network error downloading database: {e}")

        self.last_updated = time.time()
        logger.info(f"🚀 [DB] Database Ready. Total Indexed Threats: {len(self.blacklist)}")

    def check_url(self, url: str) -> bool:
        """
        Returns True if the URL or its domain is in the phishing database.
        """
        # 1. Exact URL Match
        if url in self.blacklist:
            return True
            
        # 2. Domain Match (Strip http/https and paths)
        try:
            domain = url.split("//")[-1].split("/")[0].split(":")[0]
            if domain in self.blacklist:
                return True
        except Exception:
            pass
            
        return False

    def get_db_stats(self) -> dict:
        """Return current database statistics."""
        return {
            "total_threats": len(self.blacklist),
            "last_updated": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_updated))
        }


# Create a singleton instance
# This runs immediately when the file is imported
phishing_db = PhishingDatabase()

# --- AUTO-REFRESH SCHEDULER (every 6 hours) ---
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    func=phishing_db.refresh_database,
    trigger='interval',
    hours=6,
    id='phishing_db_refresh',
    name='Phishing DB Auto-Refresh',
    replace_existing=True
)
scheduler.start()
logger.info("🕐 [DB] Auto-refresh scheduler started (every 6 hours)")