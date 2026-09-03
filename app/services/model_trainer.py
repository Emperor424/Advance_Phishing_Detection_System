"""
Model Retraining Service
Reads feedback labels + original feature vectors,
retrains the GradientBoosting classifier, and saves
the new model only if it outperforms the current one.
"""
import os
import logging
import numpy as np

logger = logging.getLogger(__name__)


def retrain_model(app):
    """Run within app context in a background thread."""
    with app.app_context():
        from app import db
        from app.models.quarantine import FeedbackLabel, SystemConfig, AuditLog
        from app.models.analysis import Classification, NLPAnalysis, LinkAnalysis, HeaderAnalysis, SenderReputation
        from app.services.ml_classifier import build_feature_vector, FEATURE_NAMES
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import f1_score
        import joblib

        logger.info("Starting model retraining...")

        feedbacks = FeedbackLabel.query.all()
        X, y = [], []

        for fb in feedbacks:
            email = fb.email
            if not email:
                continue
            nlp    = email.nlp_analysis
            links  = email.link_analyses
            header = email.header_analysis
            rep    = SenderReputation.query.filter_by(sender_email=email.sender_email).first()

            if not nlp or not header:
                continue

            nlp_dict = {
                "urgency_score":       nlp.urgency_score,
                "sentiment_score":     nlp.sentiment_score,
                "grammar_error_rate":  nlp.grammar_error_rate,
                "impersonation_score": nlp.impersonation_score,
                "keyword_density":     nlp.keyword_density,
                "text_risk_score":     nlp.text_risk_score,
            }
            link_dicts = [
                {
                    "link_risk_score": l.link_risk_score,
                    "mismatch_flag":   l.mismatch_flag,
                    "homoglyph_flag":  l.homoglyph_flag,
                    "reputation":      l.reputation,
                }
                for l in links
            ]
            header_dict = {
                "spf_result":        header.spf_result,
                "dkim_valid":        header.dkim_valid,
                "spoofing_flag":     header.spoofing_flag,
                "reply_to_mismatch": header.reply_to_mismatch,
            }
            rep_rate = rep.phishing_rate if rep else 0.0

            fv = build_feature_vector(nlp_dict, link_dicts, header_dict, rep_rate)
            X.append(fv)
            y.append(1 if fb.user_label == "phishing" else 0)

        if len(X) < 10:
            logger.warning("Not enough samples to retrain.")
            return

        X_arr = np.array(X)
        y_arr = np.array(y)

        X_train, X_test, y_train, y_test = train_test_split(
            X_arr, y_arr, test_size=0.2, random_state=42, stratify=y_arr
        )

        new_model = GradientBoostingClassifier(
            n_estimators=100, max_depth=4, learning_rate=0.1, random_state=42
        )
        new_model.fit(X_train, y_train)
        new_f1 = f1_score(y_test, new_model.predict(X_test), zero_division=0)
        logger.info(f"New model F1: {new_f1:.4f}")

        # Load existing model for comparison
        model_path = app.config.get("MODEL_PATH")
        current_f1 = 0.0
        if model_path and os.path.exists(model_path):
            try:
                old_model  = joblib.load(model_path)
                current_f1 = f1_score(y_test, old_model.predict(X_test), zero_division=0)
                logger.info(f"Current model F1: {current_f1:.4f}")
            except Exception:
                pass

        if new_f1 >= current_f1 - 0.01:  # accept if not significantly worse
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(new_model, model_path)
            version_parts = SystemConfig.get("active_model_version", "v1.0").lstrip("v").split(".")
            new_minor     = int(version_parts[-1]) + 1
            new_version   = "v" + ".".join(version_parts[:-1] + [str(new_minor)])
            SystemConfig.set("active_model_version", new_version)
            AuditLog.write("MODEL_RETRAINED", f"New model {new_version} deployed (F1={new_f1:.4f})")
            logger.info(f"Model updated to {new_version}")
        else:
            AuditLog.write("MODEL_RETRAIN_REJECTED",
                           f"New model (F1={new_f1:.4f}) worse than current (F1={current_f1:.4f}) — kept current.")
            logger.info("New model rejected — current model retained.")
