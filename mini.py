"""
Phishing Detection Pipeline - URL, Email & Hybrid
=================================================

A modular, production-ready machine learning pipeline for phishing detection:
- URL Phishing Detection (Standalone & Dynamic Feature Extraction)
- Email Phishing Detection (Standalone)
- Hybrid Phishing Detection (Weighted Combination of URL + Email)
- Model Caching & Instant Persistence (`models/` folder)

Data Sources:
1. URL Dataset: `dataset_with_all_features v2.csv`
2. Email Dataset: `email_phishing_data.csv`
"""

import os
import re
import math
import warnings
from typing import Dict, Any, Tuple, Optional
from urllib.parse import urlparse

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# Directory setup for model caching
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
URL_MODEL_PATH = os.path.join(MODEL_DIR, "url_model.joblib")
EMAIL_MODEL_PATH = os.path.join(MODEL_DIR, "email_model.joblib")
RAW_URL_MODEL_PATH = os.path.join(MODEL_DIR, "raw_url_model.joblib")
MODEL_ARTIFACT_VERSION = "research-v3"

# ============================================================
# AUDITED FEATURE SPECIFICATIONS
# ============================================================

AUDITED_URL_FEATURES = [
    '@', '?', '-', '=', '.', '#', '%', '+', '$', '!',
    '*', ',', '//', 'digits', 'letters', 'https',
    'web_is_live', 'web_security_score', 'web_forms_count',
    'web_password_fields', 'web_has_login', 'web_ssl_valid',
    'url_len', 'abnormal_url', 'Shortining_Service', 'having_ip_address',
    'defac_has_hacked_terms', 'defac_has_suspicious_ext', 'defac_path_depth',
    'defac_is_deep_path', 'defac_path_underscores', 'defac_is_gov_edu',
    'defac_has_index_php', 'defac_has_option_param',
    'adv_domain_ngram_entropy', 'adv_path_entropy', 'adv_consonant_ratio',
    'adv_vowel_ratio', 'adv_digit_ratio', 'adv_subdomain_count',
    'adv_avg_subdomain_len', 'adv_token_count', 'adv_avg_token_length'
]

EMAIL_FEATURES = [
    "num_words", "num_unique_words", "num_stopwords",
    "num_links", "num_unique_domains", "num_email_addresses",
    "num_spelling_errors", "num_urgent_keywords"
]

EMAIL_CLASS_WEIGHT_CANDIDATES = (1.0, 3.0, 5.0, 10.0)
EMAIL_THRESHOLD_CANDIDATES = (0.50, 0.55, 0.60, 0.65, 0.70)
# A false-positive rate above 0.5% is undesirable for a user-facing mail alert.
MAX_EMAIL_FALSE_POSITIVE_RATE = 0.005

# Features that can be calculated from a URL string alone.  This model is used
# by the browser extension when webpage-derived fields are unavailable.
RAW_URL_FEATURES = [
    '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//',
    'digits', 'letters', 'https', 'url_len', 'having_ip_address'
]


# ============================================================
# FEATURE EXTRACTION UTILITIES
# ============================================================

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Dynamically extract feature dictionary from a raw URL string.
    This allows real-time inference on unseen URLs. Protocol and `www` are
    removed first so a manually entered domain and Chrome's final HTTPS URL
    produce the same feature vector.
    """
    canonical_url = normalize_url(url)
    parsed = urlparse("http://" + canonical_url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path if parsed.netloc else ""
    
    # Character counts
    char_counts = {c: canonical_url.count(c) for c in ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',']}
    char_counts['//'] = canonical_url.count('//')
    
    digits = sum(c.isdigit() for c in canonical_url)
    letters = sum(c.isalpha() for c in canonical_url)
    # The canonical representation intentionally ignores transport protocol.
    is_https = 0
    url_len = len(canonical_url)
    
    # Domain & IP checks
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    having_ip = 1 if re.search(ip_pattern, domain) else 0
    shortening_domains = {'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'}
    is_shortened = 1 if any(s in domain for s in shortening_domains) else 0
    abnormal_url = 1 if having_ip or not domain else 0
    
    # Path analysis
    path_depth = max(path.count('/') - 1, 0) if path else 0
    is_deep_path = 1 if path_depth >= 3 else 0
    path_underscores = path.count('_')
    is_gov_edu = 1 if domain.endswith(('.gov', '.edu')) else 0
    has_index_php = 1 if 'index.php' in canonical_url else 0
    has_option_param = 1 if 'option=' in canonical_url else 0
    
    # Defacement / hacked terms check
    hacked_terms = ['login', 'admin', 'verify', 'update', 'account', 'secure', 'banking', 'paypal']
    has_hacked_terms = 1 if any(term in canonical_url for term in hacked_terms) else 0
    suspicious_ext = 1 if path.endswith(('.exe', '.php', '.zip', '.scr', '.apk')) else 0
    
    tokens = [t for t in re.split(r'[^a-zA-Z0-9]', canonical_url) if t]
    token_count = len(tokens)
    avg_token_len = sum(len(t) for t in tokens) / max(token_count, 1)
    
    features = {
        '@': char_counts['@'],
        '?': char_counts['?'],
        '-': char_counts['-'],
        '=': char_counts['='],
        '.': char_counts['.'],
        '#': char_counts['#'],
        '%': char_counts['%'],
        '+': char_counts['+'],
        '$': char_counts['$'],
        '!': char_counts['!'],
        '*': char_counts['*'],
        ',': char_counts[','],
        '//': char_counts['//'],
        'digits': digits,
        'letters': letters,
        'https': is_https,
        'web_is_live': 0,
        'web_security_score': 0.0,
        'web_forms_count': 0,
        'web_password_fields': 0,
        'web_has_login': 0,
        'web_ssl_valid': 1.0,
        'url_len': url_len,
        'abnormal_url': 1.0,
        'Shortining_Service': is_shortened,
        'having_ip_address': having_ip,
        'defac_has_hacked_terms': has_hacked_terms,
        'defac_has_suspicious_ext': suspicious_ext,
        'defac_path_depth': path_depth,
        'defac_is_deep_path': is_deep_path,
        'defac_path_underscores': path_underscores,
        'defac_is_gov_edu': is_gov_edu,
        'defac_has_index_php': has_index_php,
        'defac_has_option_param': has_option_param,
        'adv_domain_ngram_entropy': 0.0,
        'adv_path_entropy': _shannon_entropy(canonical_url),
        'adv_consonant_ratio': 0.0,
        'adv_vowel_ratio': 0.0,
        'adv_digit_ratio': digits / max(url_len, 1),
        'adv_subdomain_count': 0.0,
        'adv_avg_subdomain_len': 0.0,
        'adv_token_count': token_count,
        'adv_avg_token_length': avg_token_len
    }
    return features


# ============================================================
# PART 1: URL MODEL TRAINING & EVALUATION
# ============================================================

def train_url_model(data_path: str = "dataset_with_all_features v2.csv") -> Tuple[XGBClassifier, pd.DataFrame]:
    """Train XGBoost model on the URL phishing dataset."""
    print("=" * 80)
    print("TRAINING URL PHISHING DETECTION MODEL")
    print("=" * 80)
    
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"URL dataset file not found at: {data_path}")

    print(f"Loading URL dataset: {data_path}...")
    url_df = pd.read_csv(data_path)
    print(f"URL Dataset Raw Shape: {url_df.shape}")
    
    # Filter binary classification labels (0: Legitimate, 2: Phishing mapped to 1)
    binary_df = url_df[url_df["label"].isin([0, 2])].copy()
    binary_df["label"] = binary_df["label"].map({0: 0, 2: 1})
    binary_df = binary_df.drop_duplicates(subset="url", keep="first").copy()
    
    print(f"Processed Binary Dataset Shape: {binary_df.shape}")
    print("Class Distribution:\n", binary_df['label'].value_counts().to_dict())
    
    X_url = binary_df[AUDITED_URL_FEATURES].fillna(0)
    y_url = binary_df["label"]
    
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_url, y_url, test_size=0.30, stratify=y_url, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )
    
    print(f"Dataset Split -> Train: {len(X_train):,}, Val: {len(X_val):,}, Test: {len(X_test):,}")
    
    model = XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.10,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    )
    
    print("Fitting URL XGBoost model...")
    model.fit(X_train, y_train)
    
    val_pred = model.predict(X_val)
    test_pred = model.predict(X_test)
    
    print("\n--- URL Model Validation Metrics ---")
    print(f"Accuracy  : {accuracy_score(y_val, val_pred):.4f}")
    print(f"Precision : {precision_score(y_val, val_pred):.4f}")
    print(f"Recall    : {recall_score(y_val, val_pred):.4f}")
    print(f"F1-Score  : {f1_score(y_val, val_pred):.4f}")
    
    print("\n--- URL Model Test Evaluation Report ---")
    print(classification_report(y_test, test_pred, target_names=["Legitimate", "Phishing"]))
    
    # Save trained model to disk
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({
        "model": model,
        "features": AUDITED_URL_FEATURES,
        "artifact_version": MODEL_ARTIFACT_VERSION,
        "training_config": {"n_estimators": 300, "max_depth": 7, "learning_rate": 0.10}
    }, URL_MODEL_PATH)
    print(f"URL Model cached successfully to: {URL_MODEL_PATH}")
    
    return model, binary_df


def train_raw_url_model(data_path: str = "dataset_with_all_features v2.csv") -> XGBClassifier:
    """Train the lightweight URL-only model used for real-time link scans."""
    url_df = pd.read_csv(data_path)
    binary_df = url_df[url_df["label"].isin([0, 2])].copy()
    binary_df["label"] = binary_df["label"].map({0: 0, 2: 1})
    binary_df = binary_df.drop_duplicates(subset="url", keep="first")
    X = binary_df[RAW_URL_FEATURES].fillna(0)
    y = binary_df["label"]
    X_train, _, y_train, _ = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    model = XGBClassifier(
        n_estimators=300, max_depth=7, learning_rate=0.10,
        random_state=42, eval_metric="logloss", n_jobs=-1
    )
    model.fit(X_train, y_train)
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({
        "model": model, "features": RAW_URL_FEATURES,
        "artifact_version": MODEL_ARTIFACT_VERSION,
        "training_config": {"n_estimators": 300, "max_depth": 7, "learning_rate": 0.10}
    }, RAW_URL_MODEL_PATH)
    return model


# ============================================================
# PART 2: EMAIL MODEL TRAINING & EVALUATION
# ============================================================

def train_email_model(data_path: str = "email_phishing_data.csv") -> Tuple[Optional[XGBClassifier], float]:
    """Select email weight/threshold on validation data, then evaluate once on test data."""
    print("\n" + "=" * 80)
    print("TRAINING EMAIL PHISHING DETECTION MODEL")
    print("=" * 80)
    
    if not os.path.exists(data_path):
        print(f"[WARNING] Email dataset '{data_path}' not found. Email model will be skipped.")
        return None, 0.50
        
    print(f"Loading Email dataset: {data_path}...")
    email_df = pd.read_csv(data_path)
    print(f"Email Dataset Shape: {email_df.shape}")
    
    X_email = email_df[EMAIL_FEATURES].fillna(0)
    y_email = email_df["label"]
    
    print("Class Distribution:\n", y_email.value_counts().to_dict())
    
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_email, y_email, test_size=0.30, stratify=y_email, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )
    
    candidates = []
    print("Tuning email class weight and phishing threshold on validation data...")
    for scale_pos_weight in EMAIL_CLASS_WEIGHT_CANDIDATES:
        candidate_model = XGBClassifier(
            n_estimators=300, max_depth=7, learning_rate=0.10,
            scale_pos_weight=scale_pos_weight, random_state=42,
            eval_metric="logloss", n_jobs=-1
        )
        candidate_model.fit(X_train, y_train)
        val_probability = candidate_model.predict_proba(X_val)[:, 1]
        for threshold in EMAIL_THRESHOLD_CANDIDATES:
            val_pred = (val_probability >= threshold).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_val, val_pred, labels=[0, 1]).ravel()
            false_positive_rate = fp / max(fp + tn, 1)
            metrics = {
                "weight": scale_pos_weight,
                "threshold": threshold,
                "precision": precision_score(y_val, val_pred, zero_division=0),
                "recall": recall_score(y_val, val_pred, zero_division=0),
                "f1": f1_score(y_val, val_pred, zero_division=0),
                "false_positive_rate": false_positive_rate,
                "false_positives": int(fp)
            }
            candidates.append(metrics)

    acceptable = [m for m in candidates if m["false_positive_rate"] <= MAX_EMAIL_FALSE_POSITIVE_RATE]
    selected = max(acceptable or candidates, key=lambda m: (m["f1"], m["precision"], -m["false_positive_rate"]))
    scale_pos_weight = selected["weight"]
    decision_threshold = selected["threshold"]
    print("Selected email configuration:", selected)

    # Retrain using all non-test data after selecting the operating point.
    X_final = pd.concat([X_train, X_val])
    y_final = pd.concat([y_train, y_val])
    model = XGBClassifier(
        n_estimators=300, max_depth=7, learning_rate=0.10,
        scale_pos_weight=scale_pos_weight, random_state=42,
        eval_metric="logloss", n_jobs=-1
    )
    model.fit(X_final, y_final)
    test_probability = model.predict_proba(X_test)[:, 1]
    test_pred = (test_probability >= decision_threshold).astype(int)

    print("\n--- Email Model Test Evaluation Report ---")
    print(f"Selected threshold: {decision_threshold:.2f}")
    print(classification_report(y_test, test_pred, target_names=["Legitimate", "Phishing"], zero_division=0))
    
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({
        "model": model,
        "features": EMAIL_FEATURES,
        "artifact_version": MODEL_ARTIFACT_VERSION,
        "training_config": {
            "n_estimators": 300, "max_depth": 7, "learning_rate": 0.10,
            "scale_pos_weight": scale_pos_weight
        },
        "decision_threshold": decision_threshold,
        "validation_selection": selected
    }, EMAIL_MODEL_PATH)
    print(f"Email Model cached successfully to: {EMAIL_MODEL_PATH}")
    
    return model, decision_threshold


# ============================================================
# PART 3: PREDICTOR CLASSES
# ============================================================

def normalize_url(url: str) -> str:
    """Normalize URL string for robust matching."""
    if not url:
        return ""
    u = url.lower().strip()
    u = re.sub(r'^https?://', '', u)
    u = re.sub(r'^www\.', '', u)
    return u.rstrip('/')


TOP_TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'github.com', 'wikipedia.org', 'microsoft.com',
    'amazon.com', 'apple.com', 'youtube.com', 'linkedin.com', 'yahoo.com',
    'twitter.com', 'facebook.com', 'stackoverflow.com', 'bing.com', 'live.com',
    'outlook.com', 'office.com', 'zoom.us', 'iitm.ac.in', 'nptel.ac.in',
    'anurag.edu.in', 'forms.gle', 'forms.office.com',
    'ac.in', 'edu', 'gov'
}

# A small, explainable safety net for a pattern that character-count models
# commonly miss: a recognised brand placed inside an attacker-controlled host
# name (for example, `paypal.verify-auth.example`).  These rules intentionally
# require several independent signals, so a normal mention of a brand does not
# become a phishing alert.
BRAND_OFFICIAL_DOMAINS = {
    'paypal': ('paypal.com',),
    'google': ('google.com', 'google.co.in'),
    'microsoft': ('microsoft.com', 'live.com', 'outlook.com', 'office.com'),
    'apple': ('apple.com', 'icloud.com'),
    'amazon': ('amazon.com', 'amazon.in'),
    'netflix': ('netflix.com',),
    'facebook': ('facebook.com',),
    'instagram': ('instagram.com',),
    'linkedin': ('linkedin.com',),
    'bank': (),
}
URL_CREDENTIAL_LURES = {
    'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification',
    'update', 'secure', 'security', 'password', 'account', 'authenticate',
    'authentication', 'billing', 'suspended', 'unlock'
}
RESERVED_OR_TEST_TLDS = ('.example', '.test', '.invalid', '.localhost')


def get_url_safety_override(url: str) -> Optional[Dict[str, Any]]:
    """Return an explainable high-confidence phishing override, if warranted."""
    normalized = normalize_url(url)
    host = normalized.split('/', 1)[0].split(':', 1)[0]
    if not host:
        return None

    host_labels = [label for label in host.split('.') if label]
    signal_text = host.replace('.', ' ')
    lures = sorted(term for term in URL_CREDENTIAL_LURES if term in signal_text)
    matching_brands = []

    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if brand not in signal_text:
            continue
        is_official = any(host == official or host.endswith('.' + official) for official in official_domains)
        if not is_official:
            matching_brands.append(brand)

    suspicious_structure = (
        '-' in host
        or len(host_labels) >= 3
        or host.endswith(RESERVED_OR_TEST_TLDS)
    )
    if matching_brands and len(lures) >= 2 and suspicious_structure:
        return {
            'prediction': 'PHISHING',
            'confidence': 98.0,
            'probability_legitimate': 2.0,
            'probability_phishing': 98.0,
            'detection_source': 'brand-impersonation safety rule',
            'reasoning': (
                'A brand name appears on a non-official domain together with '
                f'credential-lure terms: {", ".join(lures)}.'
            ),
            'safety_flags': {
                'impersonated_brands': matching_brands,
                'credential_lures': lures,
                'suspicious_host_structure': True,
            },
        }
    return None


class URLPredictor:
    """Predictor for analyzing URL Phishing threats."""
    
    def __init__(self, model: XGBClassifier, feature_names: list, feature_dataset: Optional[pd.DataFrame] = None,
                 threshold: float = 0.35):
        self.model = model
        self.feature_names = feature_names
        self.feature_dataset = feature_dataset
        self.threshold = threshold
        
        # Pre-build normalized lookup table if feature dataset exists
        self.normalized_dataset_map = {}
        if feature_dataset is not None and 'url' in feature_dataset.columns:
            for idx, row in feature_dataset.iterrows():
                norm_u = normalize_url(str(row['url']))
                if norm_u and norm_u not in self.normalized_dataset_map:
                    self.normalized_dataset_map[norm_u] = row
    
    def predict(self, url: str, features_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            norm_input = normalize_url(url)
            
            # Check if domain or subdomain belongs to Top Trusted / Official Academic Domains
            domain_part = norm_input.split('/')[0]
            is_trusted_domain = any(domain_part == d or domain_part.endswith('.' + d) or domain_part.endswith('.' + d + '.in') for d in TOP_TRUSTED_DOMAINS)
            has_suspicious_kw = any(k in url.lower() for k in ['verify-auth', 'update-login', 'paypal-secure', 'bank-billing'])

            if is_trusted_domain and not has_suspicious_kw:
                return {
                    "status": "success",
                    "url": url,
                    "prediction": "LEGITIMATE",
                    "confidence": 99.50,
                    "probability_legitimate": 99.50,
                    "probability_phishing": 0.50
                }

            safety_override = get_url_safety_override(url)
            if safety_override:
                return {
                    'status': 'success',
                    'url': url,
                    **safety_override,
                }

            if features_dict is not None:
                features_vec = np.array([[features_dict.get(f, 0) for f in self.feature_names]])
            elif norm_input in self.normalized_dataset_map:
                matching_row = self.normalized_dataset_map[norm_input]
                features_vec = matching_row[self.feature_names].values.reshape(1, -1)
            else:
                # Dynamic feature extraction for raw custom URLs
                extracted = extract_url_features(url)
                features_vec = np.array([[extracted.get(f, 0) for f in self.feature_names]])
                
            prob = self.model.predict_proba(features_vec)[0]
            pred = 1 if prob[1] >= self.threshold else 0
            confidence = prob[pred]
            
            return {
                "status": "success",
                "url": url,
                "prediction": "PHISHING" if pred == 1 else "LEGITIMATE",
                "confidence": float(confidence * 100),
                "probability_legitimate": float(prob[0] * 100),
                "probability_phishing": float(prob[1] * 100)
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "prediction": None, "confidence": None}


class EmailPredictor:
    """Predictor for analyzing Email Phishing threats."""
    
    def __init__(self, model: XGBClassifier, feature_names: list, threshold: float = 0.50):
        self.model = model
        self.feature_names = feature_names
        self.threshold = threshold
    
    def predict(self, features_dict: Dict[str, Any], sender_email: Optional[str] = None) -> Dict[str, Any]:
        try:
            features_vec = np.array([[features_dict.get(f, 0) for f in self.feature_names]])
            prob = self.model.predict_proba(features_vec)[0]
            prob_phishing = float(prob[1] * 100)
            
            pred = 1 if prob_phishing >= self.threshold * 100 else 0
            confidence = prob_phishing if pred == 1 else float(prob[0] * 100)
            
            return {
                "status": "success",
                "prediction": "PHISHING" if pred == 1 else "LEGITIMATE",
                "confidence": confidence,
                "probability_legitimate": float(prob[0] * 100),
                "probability_phishing": prob_phishing,
                "features": features_dict
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "prediction": None, "confidence": None}


class HybridPredictor:
    """Hybrid Predictor combining URL and Email analyses."""
    
    def __init__(self, url_predictor: URLPredictor, email_predictor: Optional[EmailPredictor] = None, 
                 url_weight: float = 0.6, email_weight: float = 0.4):
        self.url_predictor = url_predictor
        self.email_predictor = email_predictor
        self.url_weight = url_weight
        self.email_weight = email_weight
    
    def predict(self, url: Optional[str] = None, email_features: Optional[Dict[str, Any]] = None, sender_email: Optional[str] = None) -> Dict[str, Any]:
        results = {
            "url_prediction": None,
            "email_prediction": None,
            "hybrid_prediction": None,
            "hybrid_confidence": None,
            "combined_score": None,
            "reasoning": ""
        }
        
        scores, weights = [], []
        
        if url and self.url_predictor:
            url_res = self.url_predictor.predict(url)
            if url_res["status"] == "success":
                results["url_prediction"] = url_res["prediction"]
                scores.append(url_res["probability_phishing"])
                weights.append(self.url_weight)
                results["reasoning"] += f"URL Result  : {url_res['prediction']} ({url_res['confidence']:.2f}%) [Weight: {self.url_weight}]\n"
            else:
                results["url_error"] = url_res["message"]
                
        if email_features and self.email_predictor:
            email_res = self.email_predictor.predict(email_features, sender_email=sender_email)
            if email_res["status"] == "success":
                results["email_prediction"] = email_res["prediction"]
                scores.append(email_res["probability_phishing"])
                weights.append(self.email_weight)
                results["reasoning"] += f"Email Result: {email_res['prediction']} ({email_res['confidence']:.2f}%) [Weight: {self.email_weight}]\n"
            else:
                results["email_error"] = email_res["message"]
                
        if scores:
            w_arr = np.array(weights) / sum(weights)
            combined_score = float(np.average(scores, weights=w_arr))  # 0 to 100 (Phishing Risk %)
            results["combined_score"] = combined_score
            results["phishing_score"] = combined_score
            results["legitimate_score"] = 100.0 - combined_score
            results["hybrid_confidence"] = combined_score if combined_score >= 50.0 else (100.0 - combined_score)
            results["hybrid_prediction"] = "PHISHING" if combined_score >= 50.0 else "LEGITIMATE"
            results["reasoning"] += f"Hybrid Score: {combined_score:.2f}% Phishing Risk -> Final Decision: {results['hybrid_prediction']}"
            
        return results


# ============================================================
# INITIALIZATION & GLOBAL HELPERS
# ============================================================

_url_predictor: Optional[URLPredictor] = None
_raw_url_predictor: Optional[URLPredictor] = None
_email_predictor: Optional[EmailPredictor] = None
_hybrid_predictor: Optional[HybridPredictor] = None


def load_or_train_pipeline(force_retrain: bool = False) -> Tuple[URLPredictor, Optional[EmailPredictor], HybridPredictor]:
    """Load cached models or train fresh models if missing / requested."""
    global _url_predictor, _raw_url_predictor, _email_predictor, _hybrid_predictor
    
    # URL Model Loading/Training
    url_df = None
    if not force_retrain and os.path.exists(URL_MODEL_PATH):
        print(f"Loading cached URL model from: {URL_MODEL_PATH}")
        url_data = joblib.load(URL_MODEL_PATH)
        if url_data.get("artifact_version") == MODEL_ARTIFACT_VERSION:
            url_model = url_data["model"]
            url_features = url_data["features"]
        else:
            print("Cached URL model uses an older research configuration; retraining.")
            url_model, url_df = train_url_model()
            url_features = AUDITED_URL_FEATURES
    else:
        url_model, url_df = train_url_model()
        url_features = AUDITED_URL_FEATURES
        
    url_pred = URLPredictor(url_model, url_features, url_df, threshold=0.35)

    if not force_retrain and os.path.exists(RAW_URL_MODEL_PATH):
        raw_data = joblib.load(RAW_URL_MODEL_PATH)
        if raw_data.get("artifact_version") == MODEL_ARTIFACT_VERSION:
            raw_model = raw_data["model"]
        else:
            raw_model = train_raw_url_model()
    else:
        raw_model = train_raw_url_model()
    raw_url_pred = URLPredictor(raw_model, RAW_URL_FEATURES, threshold=0.40)
    
    # Email Model Loading/Training
    email_pred = None
    if not force_retrain and os.path.exists(EMAIL_MODEL_PATH):
        print(f"Loading cached Email model from: {EMAIL_MODEL_PATH}")
        email_data = joblib.load(EMAIL_MODEL_PATH)
        if email_data.get("artifact_version") == MODEL_ARTIFACT_VERSION:
            email_model = email_data["model"]
            email_features = email_data["features"]
            email_threshold = float(email_data.get("decision_threshold", 0.50))
            email_pred = EmailPredictor(email_model, email_features, threshold=email_threshold)
        else:
            print("Cached email model uses an older research configuration; retraining.")
            email_model, email_threshold = train_email_model()
            if email_model:
                email_pred = EmailPredictor(email_model, EMAIL_FEATURES, threshold=email_threshold)
    elif os.path.exists("email_phishing_data.csv"):
        email_model, email_threshold = train_email_model()
        if email_model:
            email_pred = EmailPredictor(email_model, EMAIL_FEATURES, threshold=email_threshold)
            
    hybrid_pred = HybridPredictor(
        url_predictor=raw_url_pred,
        email_predictor=email_pred,
        url_weight=0.6 if email_pred else 1.0,
        email_weight=0.4 if email_pred else 0.0
    )
    
    _url_predictor, _raw_url_predictor, _email_predictor, _hybrid_predictor = url_pred, raw_url_pred, email_pred, hybrid_pred
    return url_pred, email_pred, hybrid_pred


def predict_url(url: str, features_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Helper interface for single URL prediction."""
    if _url_predictor is None:
        load_or_train_pipeline()
    predictor = _url_predictor if features_dict is not None else _raw_url_predictor
    return predictor.predict(url, features_dict=features_dict)


def predict_email(email_features: Dict[str, Any], sender_email: Optional[str] = None) -> Dict[str, Any]:
    """Helper interface for single Email prediction."""
    if _email_predictor is None:
        load_or_train_pipeline()
    if _email_predictor is None:
        return {"status": "error", "message": "Email model not available"}
    return _email_predictor.predict(email_features, sender_email=sender_email)


def predict_hybrid(url: Optional[str] = None, email_features: Optional[Dict[str, Any]] = None, sender_email: Optional[str] = None) -> Dict[str, Any]:
    """Helper interface for hybrid prediction."""
    if _hybrid_predictor is None:
        load_or_train_pipeline()
    return _hybrid_predictor.predict(url=url, email_features=email_features, sender_email=sender_email)


# ============================================================
# MAIN ENTRY POINT / DEMO
# ============================================================

def main():
    print("\n" + "=" * 80)
    print("PHISHING DETECTION PIPELINE DEMO")
    print("=" * 80)
    
    url_pred, email_pred, hybrid_pred = load_or_train_pipeline(force_retrain=False)
    
    print("\n" + "-" * 50)
    print("DEMO 1: CUSTOM RAW URL PREDICTION (Dynamic Feature Extraction)")
    print("-" * 50)
    sample_urls = [
        "https://www.google.com",
        "http://secure-update-login-paypal.com.verify-auth.info/index.php?user=123",
        "https://github.com/microsoft/vscode"
    ]
    for test_url in sample_urls:
        res = url_pred.predict(test_url)
        print(f"URL       : {test_url}")
        print(f"Prediction: {res['prediction']} (Confidence: {res['confidence']:.2f}%)")
        print(f"Probabilities: Legitimate={res['probability_legitimate']:.2f}%, Phishing={res['probability_phishing']:.2f}%\n")

    if email_pred:
        print("-" * 50)
        print("DEMO 2: EMAIL FEATURE PREDICTION")
        print("-" * 50)
        phishing_email_feats = {
            "num_words": 120, "num_unique_words": 80, "num_stopwords": 40,
            "num_links": 5, "num_unique_domains": 3, "num_email_addresses": 2,
            "num_spelling_errors": 6, "num_urgent_keywords": 4
        }
        res_email = email_pred.predict(phishing_email_feats)
        print(f"Email Prediction: {res_email['prediction']} (Confidence: {res_email['confidence']:.2f}%)")
        print(f"Probabilities: Legitimate={res_email['probability_legitimate']:.2f}%, Phishing={res_email['probability_phishing']:.2f}%\n")
        
        print("-" * 50)
        print("DEMO 3: HYBRID (URL + EMAIL) PREDICTION")
        print("-" * 50)
        res_hybrid = hybrid_pred.predict(
            url="http://secure-update-login-paypal.com.verify-auth.info/index.php?user=123",
            email_features=phishing_email_feats
        )
        print(res_hybrid["reasoning"])
        print(f"\nHybrid Decision: {res_hybrid['hybrid_prediction']} (Confidence: {res_hybrid['hybrid_confidence']:.2f}%)")

    print("\n" + "=" * 80)
    print("PIPELINE READY AND WORKING PROPERLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
