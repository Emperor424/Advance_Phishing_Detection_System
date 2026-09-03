"""
Initial ML Model Training Script
Run once to train the baseline phishing detection model.
Uses a synthetic dataset that mirrors real phishing characteristics.
Run: python ml/train_model.py
"""
import os
import sys
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, f1_score
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishguard_model.joblib")

FEATURE_NAMES = [
    "urgency_score",
    "sentiment_score",
    "grammar_error_rate",
    "impersonation_score",
    "keyword_density",
    "text_risk_score",
    "max_link_risk",
    "mismatch_count",
    "homoglyph_count",
    "malicious_link_count",
    "spf_fail",
    "dkim_fail",
    "spoofing",
    "reply_mismatch",
    "sender_rep_score",
]


def generate_training_data(n_samples: int = 2000):
    """
    Synthetic training data that mirrors real phishing patterns.
    Phishing emails:  high urgency, bad sentiment, grammar errors,
                      brand impersonation, link mismatches, auth failures.
    Legitimate emails: low scores across the board.
    """
    rng = np.random.RandomState(42)
    half = n_samples // 2

    # ── Phishing samples ──────────────────────────────────────────────────────
    phishing = np.column_stack([
        rng.uniform(0.5, 1.0, half),     # urgency_score
        rng.uniform(0.5, 0.9, half),     # sentiment_score (high = negative tone)
        rng.uniform(0.1, 0.6, half),     # grammar_error_rate
        rng.uniform(0.3, 1.0, half),     # impersonation_score
        rng.uniform(0.2, 0.8, half),     # keyword_density
        rng.uniform(0.5, 1.0, half),     # text_risk_score
        rng.uniform(0.4, 1.0, half),     # max_link_risk
        rng.uniform(0.3, 1.0, half),     # mismatch_count
        rng.uniform(0.0, 0.8, half),     # homoglyph_count
        rng.uniform(0.0, 0.7, half),     # malicious_link_count
        rng.choice([0, 1], half, p=[0.2, 0.8]),  # spf_fail
        rng.choice([0, 1], half, p=[0.2, 0.8]),  # dkim_fail
        rng.choice([0, 1], half, p=[0.3, 0.7]),  # spoofing
        rng.choice([0, 1], half, p=[0.4, 0.6]),  # reply_mismatch
        rng.uniform(0.4, 1.0, half),     # sender_rep_score (high = bad rep)
    ])
    y_phishing = np.ones(half, dtype=int)

    # ── Legitimate samples ────────────────────────────────────────────────────
    legit = np.column_stack([
        rng.uniform(0.0, 0.3, half),     # urgency_score
        rng.uniform(0.0, 0.3, half),     # sentiment_score
        rng.uniform(0.0, 0.1, half),     # grammar_error_rate
        rng.uniform(0.0, 0.1, half),     # impersonation_score
        rng.uniform(0.0, 0.1, half),     # keyword_density
        rng.uniform(0.0, 0.3, half),     # text_risk_score
        rng.uniform(0.0, 0.2, half),     # max_link_risk
        rng.uniform(0.0, 0.1, half),     # mismatch_count
        rng.uniform(0.0, 0.05, half),    # homoglyph_count
        rng.uniform(0.0, 0.0, half),     # malicious_link_count
        rng.choice([0, 1], half, p=[0.9, 0.1]),  # spf_fail
        rng.choice([0, 1], half, p=[0.9, 0.1]),  # dkim_fail
        rng.choice([0, 1], half, p=[0.95, 0.05]),# spoofing
        rng.choice([0, 1], half, p=[0.92, 0.08]),# reply_mismatch
        rng.uniform(0.0, 0.2, half),     # sender_rep_score
    ])
    y_legit = np.zeros(half, dtype=int)

    X = np.vstack([phishing, legit])
    y = np.concatenate([y_phishing, y_legit])

    # Shuffle
    idx = rng.permutation(n_samples)
    return X[idx], y[idx]


def train():
    print("=" * 60)
    print("  PhishGuard — Initial Model Training")
    print("=" * 60)

    print(f"\n[1/4] Generating synthetic training data ({2000} samples)...")
    X, y = generate_training_data(n_samples=2000)
    print(f"       Shape: {X.shape}  |  Phishing: {y.sum()}  Legit: {(y==0).sum()}")

    print("\n[2/4] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n[3/4] Training GradientBoostingClassifier...")
    model = GradientBoostingClassifier(
        n_estimators   = 150,
        max_depth      = 5,
        learning_rate  = 0.1,
        subsample      = 0.8,
        random_state   = 42,
    )
    model.fit(X_train, y_train)

    print("\n[4/4] Evaluating model...")
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    print(f"\nCross-Val F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Feature importance
    print("\nTop Feature Importances:")
    importances = list(zip(FEATURE_NAMES, model.feature_importances_))
    importances.sort(key=lambda x: x[1], reverse=True)
    for name, imp in importances[:10]:
        bar = "█" * int(imp * 50)
        print(f"  {name:<25} {bar} {imp:.4f}")

    # Save
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\n✓ Model saved to: {MODEL_PATH}")
    print("=" * 60)
    print("Run the Flask app now: python run.py")
    print("=" * 60)


if __name__ == "__main__":
    train()
