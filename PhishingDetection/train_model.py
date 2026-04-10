# --- NECESSARY IMPORTS ---
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import os
import sys
import numpy as np  # Import numpy for NaN handling

# ==============================================================================
# This script now trains the model on a COMBINED dataset for better accuracy.
# ==============================================================================

print("=" * 60)
print("PART 1: TRAINING THE UPGRADED PHISHING DETECTION MODEL")
print("=" * 60)

# --- STEP 1: LOAD AND COMBINE DATASETS ---
try:
    df_original = pd.read_csv('phishing_dataset_final.csv')
    print(f"✅ Original dataset loaded successfully with {len(df_original)} samples.")

    df_new_legit = pd.read_csv('legitimate_sites_dataset.csv')
    print(f"✅ New legitimate dataset loaded successfully with {len(df_new_legit)} samples.")

    df_combined = pd.concat([df_original, df_new_legit], ignore_index=True)
    print(f"✅ Datasets combined. Total training samples: {len(df_combined)}")

except FileNotFoundError as e:
    print(f"❌ Error: A dataset file was not found. {e}")
    print("Please run 'create_new_dataset.py' first to generate 'legitimate_sites_dataset.csv'.")
    sys.exit(1)
except Exception as e:
    print(f"An error occurred during file loading: {e}")
    sys.exit(1)

# --- STEP 2: PREPARE AND CLEAN DATA FOR TRAINING ---
print("Cleaning combined data...")

try:
    # --- NEW, MORE ROBUST CLEANING ---

    # 1. Define a function to clean all possible 'Result' values
    def clean_result(val):
        if isinstance(val, (int, float)):
            return val  # It's already numeric (from the new dataset)
        if isinstance(val, str):
            try:
                # This will handle "b'-1'", "b'1'", "b'0'"
                return int(val.strip("b'"))
            except ValueError:
                # This will handle clean number strings like "1", "-1"
                try:
                    return int(val)
                except ValueError:
                    return np.nan  # Mark all other cases as NaN
        return np.nan  # Handle NoneTypes or other unexpected types


    # 2. Apply the cleaner to the 'Result' column
    y_series = df_combined['Result'].apply(clean_result)

    # 3. Filter for valid labels: We only want -1 (Legit) and 1 (Phishing)
    # This will automatically drop NaNs AND the '0' (Suspicious) values
    valid_indices = y_series.loc[y_series.isin([-1, 1])].index

    y = y_series[valid_indices]
    X = df_combined.loc[valid_indices].drop('Result', axis=1)  # Align X with the filtered y

    print(
        f"✅ Kept {len(y)} valid samples ({-1, 1}). Dropped {len(df_combined) - len(y)} invalid/suspicious (0) or NaN samples.")

    # 4. Clean the feature columns (X)
    for col in X.columns:
        if X[col].dtype == 'object':
            try:
                # This should handle all 'b' strings in features
                X[col] = X[col].apply(lambda x: int(x.strip("b'")))
            except (ValueError, TypeError, AttributeError):
                # If it fails, coerce to numeric and fill NaNs with 0
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    # Ensure all X data is numeric (int or float)
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    print("✅ Combined data cleaning complete.")

    # 5. Map y to {0, 1} and ensure it's integer type
    y = y.map({-1: 0, 1: 1}).astype(int)
    print("✅ Target labels remapped to {0, 1}.")

    if 1 not in y.values:
        print("❌ CRITICAL ERROR: No phishing samples (1) found in the cleaned data. Stopping.")
        sys.exit(1)
    if 0 not in y.values:
        print("❌ CRITICAL ERROR: No legitimate samples (0) found in the cleaned data. Stopping.")
        sys.exit(1)

except KeyError:
    print("❌ Error: 'Result' column not found. Check your CSV files.")
    sys.exit(1)
except Exception as e:
    print(f"❌ An error occurred during data cleaning: {e}")
    sys.exit(1)

# --- STEP 3: SPLIT THE DATA ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"✅ Data split into training and testing sets.")

# --- STEP 4: TRAIN THE NEW, SMARTER XGBOOST MODEL ---
# The UserWarning is normal, the parameters are correct
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
print("\n🚀 Training the new, smarter XGBOOST model...")
model.fit(X_train, y_train)
print("✅ Model training complete!")

# --- STEP 5: EVALUATE MODEL PERFORMANCE ---
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n📊 Model Accuracy on Test Data: {accuracy * 100:.2f}%")
print("\nDetailed Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)']))

# --- STEP 6: SAVE THE NEWLY TRAINED MODEL ---
model_filename = "phishing_model_v2.xgb"
model.save_model(model_filename)
print(f"\n✅ New model saved successfully as '{model_filename}'")
print("You can now run 'app.py' (make sure it loads this new model file).")

