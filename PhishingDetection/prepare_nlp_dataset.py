import pandas as pd
from datasets import load_dataset
from bs4 import BeautifulSoup
import re


def clean_html(html_content):
    """
    Uses BeautifulSoup to clean HTML, removing scripts, styles,
    and extracting only the body text.
    """
    if not html_content or not isinstance(html_content, str):
        return ""

    try:
        # Use 'html.parser' for broad compatibility
        soup = BeautifulSoup(html_content, 'html.parser')

        # 1. Remove all script and style elements
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()

        # 2. Get text from the body, or all text if no body
        if soup.body:
            text = soup.body.get_text()
        else:
            text = soup.get_text()

        # 3. Clean up the text
        # Break into lines and remove leading/trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Remove empty lines
        text = '\n'.join(chunk for chunk in chunks if chunk)

        # 4. Optional: Normalize whitespace (replace multiple spaces/newlines with one)
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    except Exception as e:
        print(f"Error cleaning HTML: {e}")
        return ""


# --- Main execution ---
if __name__ == "__main__":
    print("Starting dataset download from Hugging Face...")

    # 1. Load the dataset
    # This dataset has 87k samples: 32k legitimate, 55k phishing
    try:
        dataset = load_dataset("ealvaradob/phishing-dataset", split='train')
    except Exception as e:
        print(f"Failed to download dataset. Do you have internet? Error: {e}")
        exit()

    print(f"Dataset loaded. Total samples: {len(dataset)}")

    # 2. Convert to Pandas DataFrame for easier processing
    df = pd.DataFrame(dataset)
    print("Converted to DataFrame. Starting HTML cleaning process...")

    # --- ADD THIS DEBUG LINE ---
    print(f"DEBUG: Dataset columns are: {df.columns}")
    # --- END OF DEBUG LINE ---

    print("(This may take a minute or two, please wait)...")

    # 3. Apply our cleaning function to the 'html' column
    # This is the most time-consuming step
    df['clean_text'] = df['text'].apply(clean_html)

    print("HTML cleaning complete.")

    # 4. Create the final, clean DataFrame
    # We only need the clean text and the original label
    final_df = df[['clean_text', 'label']]

    # Let's drop any rows where cleaning failed and produced no text
    final_df = final_df[final_df['clean_text'] != '']

    # 5. Save the clean dataset to a new CSV file
    output_filename = "nlp_dataset_clean.csv"
    try:
        final_df.to_csv(output_filename, index=False, encoding='utf-8')
        print("=" * 30)
        print(f"✅ SUCCESS! ✅")
        print(f"Clean dataset saved to: {output_filename}")
        print(f"Total samples processed: {len(final_df)}")
        print("\nHead of the new dataset:")
        print(final_df.head())
        print("=" * 30)

    except Exception as e:
        print(f"Error saving to CSV: {e}")