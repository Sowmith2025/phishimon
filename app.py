"""
Phishing Detection Flask API Server
====================================
Serves REST API endpoints for the Chrome Extension & local clients.
Connects directly to cached XGBoost models in mini.py.
"""

import os
os.environ["FLASK_SKIP_DOTENV"] = "1"

import re
from typing import Dict, Any
from flask import Flask, request, jsonify
from flask_cors import CORS

from mini import load_or_train_pipeline, predict_url, predict_email, predict_hybrid

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for Chrome Extension

# Pre-load cached ML models on server startup
print("Initializing Phishing Detection Models...")
load_or_train_pipeline(force_retrain=False)
print("Models ready!")

COMMON_STOPWORDS = {
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
    'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
    'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
    'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what'
}

URGENT_KEYWORDS = {
    'action required immediately', 'account suspended', 'account suspension',
    'unauthorized login', 'verify password', 'verify your password',
    'click here to unlock', 'final warning', 'security threat', 'unusual sign-in',
    'update billing immediately', 'account locked', 'suspension notice',
    'verify credentials', 'urgent action required', 'unauthorized access'
}


def extract_email_features_from_text(text: str) -> Dict[str, int]:
    """Extract 8 numerical features from raw email body text."""
    if not text:
        return {
            "num_words": 0, "num_unique_words": 0, "num_stopwords": 0,
            "num_links": 0, "num_unique_domains": 0, "num_email_addresses": 0,
            "num_spelling_errors": 0, "num_urgent_keywords": 0
        }
        
    words = re.findall(r'\b[a-zA-Z0-9_-]+\b', text)
    words_lower = [w.lower() for w in words]
    
    num_words = len(words)
    num_unique_words = len(set(words_lower))
    num_stopwords = sum(1 for w in words_lower if w in COMMON_STOPWORDS)
    
    links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text, re.IGNORECASE)
    num_links = len(links)
    
    domains = set()
    for link in links:
        d = link.split('/')[2] if '://' in link else link.split('/')[0]
        domains.add(d.lower())
    num_unique_domains = len(domains)
    
    emails = re.findall(r'[\w\.-]+@[\w\.-]+', text)
    num_email_addresses = len(emails)
    
    # Urgent keywords count
    text_lower = text.lower()
    num_urgent_keywords = sum(text_lower.count(kw) for kw in URGENT_KEYWORDS)
    
    # Simple heuristic spelling error check (words with triple repeated letters or abnormal character mixes)
    num_spelling_errors = sum(1 for w in words if re.search(r'(.)\1\1', w) or (len(w) > 12 and not any(v in w.lower() for v in 'aeiou')))
    
    return {
        "num_words": num_words,
        "num_unique_words": num_unique_words,
        "num_stopwords": num_stopwords,
        "num_links": num_links,
        "num_unique_domains": num_unique_domains,
        "num_email_addresses": num_email_addresses,
        "num_spelling_errors": num_spelling_errors,
        "num_urgent_keywords": num_urgent_keywords,
        "raw_text": text
    }


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "Phishing Detection API", "version": "1.0"})


@app.route('/api/predict/url', methods=['POST'])
def handle_predict_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"status": "error", "message": "Missing 'url' parameter"}), 400
        
    result = predict_url(url)
    return jsonify(result)


@app.route('/api/predict/email', methods=['POST'])
def handle_predict_email():
    data = request.get_json(silent=True) or {}
    email_text = data.get('email_text', '')
    sender_email = data.get('sender_email') or data.get('sender')
    features = data.get('features')
    
    if not features and email_text:
        features = extract_email_features_from_text(email_text)
    elif not features:
        return jsonify({"status": "error", "message": "Provide either 'email_text' or 'features' object"}), 400
        
    result = predict_email(features, sender_email=sender_email)
    result["extracted_features"] = features
    return jsonify(result)


@app.route('/api/predict/hybrid', methods=['POST'])
def handle_predict_hybrid():
    data = request.get_json(silent=True) or {}
    url = data.get('url')
    email_text = data.get('email_text')
    sender_email = data.get('sender_email') or data.get('sender')
    email_features = data.get('features')
    
    if not email_features and email_text:
        email_features = extract_email_features_from_text(email_text)
        
    if not url and not email_features:
        return jsonify({"status": "error", "message": "Provide 'url' and/or 'email_text'/'features'"}), 400
        
    result = predict_hybrid(url=url, email_features=email_features, sender_email=sender_email)
    if email_features:
        result["extracted_email_features"] = email_features
    return jsonify(result)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", "5000"))
    print(f"Starting Phishing Detection Flask Server on port {port} ...")
    app.run(host='0.0.0.0', port=port, debug=False)
