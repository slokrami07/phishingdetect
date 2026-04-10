import pandas as pd
from scipy.io import arff

# --- Configuration ---
arff_file_name = 'Training Dataset.arff'
csv_file_name = 'phishing_dataset_final.csv'

# --- Conversion Logic using SciPy ---
try:
    data, meta = arff.loadarff(arff_file_name)

    # Create the DataFrame directly
    df = pd.DataFrame(data)

    # The column decoding line has been removed

    df.to_csv(csv_file_name, index=False)

    print(f"✅ Successfully converted '{arff_file_name}' to '{csv_file_name}'!")

except FileNotFoundError:
    print(f"❌ Error: The file '{arff_file_name}' was not found.")

except Exception as e:
    print(f"An error occurred: {e}")