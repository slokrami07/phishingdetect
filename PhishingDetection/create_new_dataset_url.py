import pandas as pd
from app import extract_ai_features, HostScanner, SandboxScanner  # <-- Import your functions
import time
from urllib.parse import urlparse

# --- Configuration ---
# 1. Point this to your master list of URLs
# It should have two columns: 'url' and 'label' (1 for phishing, 0 for legitimate)
INPUT_CSV = 'phishing_dataset_final.csv'
OUTPUT_CSV = 'phishing_dataset_v2.csv'


# ---------------------

def process_url(url):
    """
    Runs the full analysis pipeline for a single URL.
    """
    try:
        # 1. Run Host Scan
        domain = urlparse(url).netloc
        host_scanner = HostScanner(domain)
        host_report = host_scanner.scan()

        # 2. Run Sandbox Scan
        scanner = SandboxScanner(url)
        sandbox_success = scanner.run_sandbox()

        soup = None
        if sandbox_success:
            if scanner.analyze_results():
                soup = scanner.scan_report.get('soup')

        # 3. Extract Features (using our new, updated function!)
        features = extract_ai_features(url, soup, host_report)
        return features

    except Exception as e:
        print(f"  !! Failed to process {url}: {e}")
        return None


# --- Main Script ---
print(f"Loading URLs from {INPUT_CSV}...")
try:
    df = pd.read_csv(INPUT_CSV,header=None)
except FileNotFoundError:
    print(f"ERROR: Cannot find {INPUT_CSV}. Please update the INPUT_CSV variable.")
    exit()

all_data = []
feature_columns = [f'feature_{i}' for i in range(30)]  # Creates 'feature_0', 'feature_1', ...
total_urls = len(df)

print(f"Found {total_urls} URLs. Starting feature extraction...")

for index, row in df.iterrows():
    url = row[0]
    label = row[1]

    print(f"\nProcessing [{index + 1}/{total_urls}]: {url}")

    features = process_url(url)

    if features:
        # Add the label as the last column
        all_data.append(features + [label])
        print(f"  ✅ Success. Feature 12 (Subdomain) = {features[12]}")

    # Be nice to your network and the servers
    time.sleep(2)

print("\nFeature extraction complete.")

# --- Save to new CSV ---
final_columns = feature_columns + ['label']
output_df = pd.DataFrame(all_data, columns=final_columns)
output_df.to_csv(OUTPUT_CSV, index=False)

print(f"✅ Successfully saved new dataset to {OUTPUT_CSV}!")