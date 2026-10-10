import os
import json
import sqlite3
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
import joblib

# Attempt LogisticRegression first; fall back to MultinomialNB if OS DLL policy blocks C-extension
classifier_type = "LogisticRegression"
try:
    from sklearn.linear_model import LogisticRegression
    _test_clf = LogisticRegression()
except (ImportError, Exception):
    from sklearn.naive_bayes import MultinomialNB
    classifier_type = "MultinomialNB"

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BACKEND_DIR, "models")
DATA_DIR = os.path.join(BACKEND_DIR, "data")
DB_PATH = os.path.join(BACKEND_DIR, "threatforge.db")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

def load_and_normalize_data():
    """
    Loads message data from threatforge.db using read-only URI mode,
    performs conservative normalization, deduplication, and label mapping.
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found at {DB_PATH}")

    uri = f"file:{os.path.abspath(DB_PATH)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    cursor = conn.cursor()
    cursor.execute("SELECT message, risk_level, risk_score FROM analysis_reports WHERE message IS NOT NULL")
    rows = cursor.fetchall()
    conn.close()

    raw_count = len(rows)
    records = []
    for msg, lvl, score in rows:
        text = str(msg).strip()
        if text:
            records.append({"text": text, "risk_level": lvl, "risk_score": score})

    df = pd.DataFrame(records)
    if df.empty:
        return df, 0, 0

    # 1. Exact deduplication on text
    df = df.drop_duplicates(subset=['text']).copy()
    dedup_count = len(df)

    # 2. Conservative Label normalization:
    # CRITICAL / HIGH / score >= 60 -> scam
    # LOW / score < 30 -> benign
    # MEDIUM -> excluded (uncertain / borderline)
    def map_label(level, score):
        lvl = str(level).strip().upper()
        if lvl in ['CRITICAL', 'HIGH'] or (score is not None and score >= 60):
            return 'scam'
        elif lvl == 'LOW' or (score is not None and score < 30):
            return 'benign'
        return None

    df['label'] = [map_label(lvl, sc) for lvl, sc in zip(df['risk_level'], df['risk_score'])]
    
    # Exclude uncertain / unlabelled samples
    df_clean = df[df['label'].notnull()].copy()
    
    # Save normalized dataset CSV (for reproducibility)
    clean_csv_path = os.path.join(DATA_DIR, "normalized_messages.csv")
    df_clean[['text', 'label']].to_csv(clean_csv_path, index=False)

    return df_clean, raw_count, dedup_count

def train():
    df, raw_count, dedup_count = load_and_normalize_data()

    class_counts = df['label'].value_counts().to_dict()
    total_samples = len(df)

    report = {
        "model_version": "text-v1",
        "raw_samples_found": raw_count,
        "deduplicated_samples": dedup_count,
        "labeled_supervised_samples": total_samples,
        "class_distribution": class_counts,
        "classifier_algorithm": classifier_type,
        "pipeline": f"TfidfVectorizer(ngram_range=(1,2)) + {classifier_type}",
        "random_seed": 42
    }

    scam_count = class_counts.get('scam', 0)
    benign_count = class_counts.get('benign', 0)

    print(f"Dataset stats: Raw={raw_count}, Deduplicated={dedup_count}, Supervised Labeled={total_samples}")
    print(f"Class distribution: {class_counts}")
    print(f"Selected Classifier: {classifier_type}")

    if scam_count < 2 or benign_count < 2:
        report["status"] = "INSUFFICIENT_DATA"
        report["limitation"] = "Dataset does not have enough distinct samples per class for training/testing."
        with open(os.path.join(MODEL_DIR, "training_report.json"), "w") as f:
            json.dump(report, f, indent=2)
        print("Training aborted: Insufficient labeled data for both classes.")
        return

    # Check if dataset is large enough for a holdout split
    if total_samples >= 10 and scam_count >= 3 and benign_count >= 3:
        X_train, X_test, y_train, y_test = train_test_split(
            df['text'], df['label'],
            test_size=0.25,
            random_state=42,
            stratify=df['label']
        )
        has_eval_split = True
        report["split_details"] = {
            "train_count": len(X_train),
            "test_count": len(X_test),
            "test_ratio": 0.25
        }
    else:
        X_train, y_train = df['text'], df['label']
        X_test, y_test = df['text'], df['label']
        has_eval_split = False
        report["split_details"] = {
            "train_count": len(X_train),
            "test_count": 0,
            "limitation": "Dataset is small seed dataset. Full dataset used for training, hold-out split not statistically meaningful."
        }

    # Instantiate classifier
    if classifier_type == "LogisticRegression":
        clf = LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000)
    else:
        from sklearn.naive_bayes import MultinomialNB
        clf = MultinomialNB()

    # Pipeline definition: TfidfVectorizer + Classifier
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True
        )),
        ('clf', clf)
    ])

    pipeline.fit(X_train, y_train)

    if has_eval_split:
        y_pred = pipeline.predict(X_test)
        p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
        cm = confusion_matrix(y_test, y_pred, labels=['benign', 'scam']).tolist()
        report["evaluation_metrics"] = {
            "weighted_precision": round(float(p), 4),
            "weighted_recall": round(float(r), 4),
            "weighted_f1": round(float(f1), 4),
            "confusion_matrix": {
                "labels": ["benign", "scam"],
                "matrix": cm
            }
        }
        print(f"Evaluation: Precision={p:.4f}, Recall={r:.4f}, F1={f1:.4f}")
    else:
        report["evaluation_metrics"] = {
            "note": "Evaluation metrics deferred until larger dataset is collected."
        }

    report["status"] = "SUCCESS"

    # Save model pipeline
    model_path = os.path.join(MODEL_DIR, "scam_classifier_v1.joblib")
    joblib.dump(pipeline, model_path)
    report["model_path"] = "models/scam_classifier_v1.joblib"

    # Save training report
    report_path = os.path.join(MODEL_DIR, "training_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Model saved to: {model_path}")
    print(f"Report saved to: {report_path}")

if __name__ == "__main__":
    train()
