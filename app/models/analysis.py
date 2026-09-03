from datetime import datetime
from app import db


class NLPAnalysis(db.Model):
    __tablename__ = "nlp_analysis"

    analysis_id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id             = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False, unique=True)
    urgency_score        = db.Column(db.Float, default=0.0)
    sentiment_score      = db.Column(db.Float, default=0.0)
    grammar_error_rate   = db.Column(db.Float, default=0.0)
    impersonation_score  = db.Column(db.Float, default=0.0)
    keyword_density      = db.Column(db.Float, default=0.0)
    suspicious_keywords  = db.Column(db.Text, nullable=True)
    text_risk_score      = db.Column(db.Float, default=0.0)
    analysed_at          = db.Column(db.DateTime, default=datetime.utcnow)


class LinkAnalysis(db.Model):
    __tablename__ = "link_analysis"

    link_id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id        = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False)
    anchor_text     = db.Column(db.Text, nullable=True)
    href_url        = db.Column(db.Text, nullable=True)
    final_url       = db.Column(db.Text, nullable=True)
    mismatch_flag   = db.Column(db.Boolean, default=False)
    reputation      = db.Column(db.String(50), default="unknown")
    homoglyph_flag  = db.Column(db.Boolean, default=False)
    suspicious_tld  = db.Column(db.Boolean, default=False)
    link_risk_score = db.Column(db.Float, default=0.0)


class HeaderAnalysis(db.Model):
    __tablename__ = "header_analysis"

    header_id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id            = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False, unique=True)
    spf_result          = db.Column(db.String(50), default="none")
    dkim_valid          = db.Column(db.Boolean, default=False)
    dmarc_policy        = db.Column(db.String(50), default="none")
    spoofing_flag       = db.Column(db.Boolean, default=False)
    reply_to_mismatch   = db.Column(db.Boolean, default=False)
    routing_anomaly     = db.Column(db.Boolean, default=False)
    sender_domain       = db.Column(db.String(255), nullable=True)
    display_name        = db.Column(db.String(255), nullable=True)
    header_risk_score   = db.Column(db.Float, default=0.0)
    analysed_at         = db.Column(db.DateTime, default=datetime.utcnow)


class SenderReputation(db.Model):
    __tablename__ = "sender_reputation"

    rep_id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_email   = db.Column(db.String(255), nullable=False, unique=True)
    sender_domain  = db.Column(db.String(255), nullable=False)
    total_emails   = db.Column(db.Integer, default=1)
    phishing_count = db.Column(db.Integer, default=0)
    phishing_rate  = db.Column(db.Float, default=0.0)
    rep_badge      = db.Column(db.String(50), default="neutral")
    last_seen      = db.Column(db.DateTime, default=datetime.utcnow)

    def update_reputation(self, is_phishing: bool):
        self.total_emails += 1
        if is_phishing:
            self.phishing_count += 1
        self.phishing_rate = self.phishing_count / self.total_emails
        self.last_seen = datetime.utcnow()
        # Badge logic
        r = self.phishing_rate
        if r <= 0.1:
            self.rep_badge = "trusted"
        elif r <= 0.4:
            self.rep_badge = "neutral"
        elif r <= 0.7:
            self.rep_badge = "suspicious"
        else:
            self.rep_badge = "known-bad"


class Classification(db.Model):
    __tablename__ = "classifications"

    classification_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id          = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False, unique=True)
    risk_score        = db.Column(db.Float, default=0.0)
    label             = db.Column(db.String(50), default="safe")
    top_feature_1     = db.Column(db.String(100), nullable=True)
    top_feature_2     = db.Column(db.String(100), nullable=True)
    top_feature_3     = db.Column(db.String(100), nullable=True)
    explanation_text  = db.Column(db.Text, nullable=True)
    model_version     = db.Column(db.String(50), default="v1.0")
    classified_at     = db.Column(db.DateTime, default=datetime.utcnow)
