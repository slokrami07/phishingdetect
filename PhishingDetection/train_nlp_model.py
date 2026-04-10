import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report
import joblib  # Used for saving the model

# --- Main execution ---
if __name__ == "__main__":
    DATASET_FILE = "nlp_dataset_clean.csv"
    MODEL_FILE = "nlp_model_v1.pkl"

    print(f"Loading clean dataset: {DATASET_FILE}...")
    try:
        df = pd.read_csv(DATASET_FILE)
    except FileNotFoundError:
        print(f"Error: Could not find {DATASET_FILE}")
        print("Please make sure you ran 'prepare_nlp_dataset.py' first.")
        exit()

    # --- Data Pre-processing ---

    # 1. Handle potential empty text (NaN values) that might have resulted from cleaning
    # We fill them with an empty string, so the vectorizer can handle them
    df['clean_text'] = df['clean_text'].fillna('')

    # 2. Drop any rows where the label is missing (just in case)
    df = df.dropna(subset=['label'])

    # 3. Define our features (X) and target (y)
    X = df['clean_text']
    y = df['label']

    print(f"Dataset loaded. Total samples: {len(df)}")
    if len(df) == 0:
        print("Error: The dataset is empty. Cannot train.")
        exit()

    print("Splitting data into training and testing sets (80/20)...")
    # 4. Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- Model Definition ---
    print("Defining the NLP model pipeline (TfidfVectorizer + LogisticRegression)...")

    # Create the pipeline. This is our entire "Stream 2" model.
    # 1. TfidfVectorizer: Converts text to numbers.
    #    - stop_words='english': Removes common words like 'the', 'is', etc.
    #    - max_features=5000: Builds a vocabulary of the top 5000 most important words.
    # 2. LogisticRegression: The classifier that makes the prediction.
    nlp_pipeline = Pipeline([
        ('vectorizer', TfidfVectorizer(stop_words='english', max_features=5000)),
        ('classifier', LogisticRegression(max_iter=1000))  # max_iter for convergence
    ])

    # --- Model Training ---
    print("Training the new AI 'brain' (Stream 2)...")
    print("(This may take a minute, it's learning from a lot of text!)...")

    # Train the *entire* pipeline on our training text
    nlp_pipeline.fit(X_train, y_train)

    print("Training complete!")

    # --- Model Evaluation ---
    print("\n--- Model Evaluation (on 20% test data) ---")
    y_pred = nlp_pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy * 100:.2f}%")

    print("\nClassification Report:")
    # This shows us Precision, Recall, and F1-score for both classes
    # '0' is legitimate, '1' is phishing
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)']))
    print("-------------------------------------------------")

    # --- Model Saving ---
    try:
        joblib.dump(nlp_pipeline, MODEL_FILE)
        print(f"\n✅ SUCCESS! ✅")
        print(f"The new AI 'brain' (Stream 2) has been trained and saved to:")
        print(f"{MODEL_FILE}")
    except Exception as e:
        print(f"Error: Failed to save the model. {e}")