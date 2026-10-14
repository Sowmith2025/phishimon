# Phishimon Project Guide

## 1. Project overview

**Phishimon** is a hybrid phishing-detection prototype. It identifies possible phishing threats from:

- a website URL;
- the text of an email; or
- both together.

The project combines machine-learning predictions with a Chrome extension that warns a user while browsing. It is designed as a decision-support tool: a `PHISHING` result means the system found a high-risk pattern, not that it has proved malicious activity beyond doubt.

## 2. Problem addressed

Phishing attackers use fake links and misleading emails to obtain passwords, bank details, and other private information. Static blacklists can miss recently created or modified attacks. Phishimon instead learns patterns from labelled phishing and legitimate examples, then applies those patterns to new input.

Two sources of evidence are important:

1. **URL evidence**: unusual structure, suspicious words, an IP address, deep paths, special characters, and similar characteristics.
2. **Email evidence**: urgent language, links, domains, addresses, word patterns, and simple spelling-pattern indicators.

## 3. High-level architecture

```text
Browser page / webmail message / manual input
                  |
                  v
        Chrome Extension (Manifest V3)
                  |
                  v
       Flask API at http://127.0.0.1:5000
                  |
      +-----------+------------+
      |                        |
      v                        v
Raw URL model             Email model
XGBoost                   XGBoost
      |                        |
      +-----------+------------+
                  |
                  v
        Hybrid late-fusion scorer
                  |
                  v
  Prediction + probabilities + browser warning
```

## 4. Repository structure

| Path | Purpose |
|---|---|
| `app.py` | Flask API server and request validation. |
| `mini.py` | Feature extraction, model training, caching, prediction classes, and hybrid scoring. |
| `dataset_with_all_features v2.csv` | URL phishing dataset. |
| `email_phishing_data.csv` | Email phishing feature dataset. |
| `models/` | Cached joblib model artifacts. |
| `extension/manifest.json` | Chrome Extension Manifest V3 configuration. |
| `extension/background.js` | Background worker that calls the API and sets browser badges. |
| `extension/content.js` | Page/webmail scanner and phishing warning-banner logic. |
| `extension/popup/` | Popup interface, styling, and manual scanner. |
| `scratch/` | Research-support scripts such as ROC and SHAP plot generation. |

## 5. Main program flow

1. Start `app.py`.
2. The server imports `load_or_train_pipeline()` from `mini.py`.
3. The pipeline loads cached model files if their saved artifact version matches the current research configuration.
4. If a model is missing or from an older configuration, the system retrains and saves it under `models/`.
5. The Chrome extension sends URL, email, or hybrid requests to the Flask API.
6. The API extracts features when raw text is provided and returns a JSON prediction.
7. The extension displays a `SAFE` or `RISK` badge, probability values, and a warning banner when necessary.

## 6. Machine-learning algorithms

### 6.1 XGBoost

The deployed classifiers use **XGBoost**, a gradient-boosted decision-tree algorithm. It builds many small decision trees sequentially. Each new tree focuses on errors made by earlier trees, allowing the model to learn non-linear relationships between features.

XGBoost is suitable here because the input is tabular numerical data rather than images or raw natural-language embeddings.

The selected training configuration is:

| Parameter | Value |
|---|---:|
| Number of estimators | 300 |
| Maximum depth | 7 |
| Learning rate | 0.10 |
| Random state | 42 |
| Evaluation metric | Log loss |

The email model selects its class weight from `1`, `3`, `5`, and `10` using validation data. This avoids assuming that a high phishing-class weight is always appropriate for normal user email.

### 6.2 Models present in the project

| Model | Input | Feature count | Main threshold | Use case |
|---|---|---:|---:|---|
| Full URL XGBoost | Audited URL vector | 43 | 0.35 | Full-feature experiments or supplied feature vectors. |
| Raw URL XGBoost | Directly extracted URL features | 18 | 0.40 | Browser and manual URL scans. |
| Email XGBoost | Extracted email vector | 8 | Validation-selected | Email-text scans. |
| Hybrid scorer | URL and/or email probabilities | N/A | 0.50 | Combined decision when both sources exist. |

### 6.3 Why multiple URL models exist

The full URL model is useful when all audited numerical fields are available in a dataset or feature object. A browser normally has only a raw URL, so the project also trains a lightweight raw-URL model using features that can be calculated immediately without crawling a webpage.

## 7. URL feature extraction

`extract_url_features()` in `mini.py` converts a raw URL into numerical values. Important signals include:

- counts of `@`, `?`, `-`, `=`, `.`, `#`, `%`, `+`, `$`, `!`, `*`, commas, and repeated slashes;
- URL length;
- digit and letter counts;
- HTTPS presence;
- whether the host resembles an IP address;
- whether a known URL-shortening domain is present;
- path depth and underscore count;
- suspicious extensions such as `.exe`, `.php`, `.zip`, `.scr`, and `.apk`;
- suspicious words such as `login`, `verify`, `update`, `account`, `secure`, `banking`, and `paypal`;
- token count, average token length, digit ratio, and path entropy.

The raw-URL model uses 18 directly available fields. The full model uses the complete audited 43-field vector.

### Example

```text
http://secure-update-login-paypal.com.verify-auth.info/index.php?user=123
```

This link contains credential-related words, several hyphens and dots, a deep path, a PHP page, and a parameter. The model evaluates all relevant signals together rather than declaring it phishing based on any single indicator.

## 8. Email feature extraction

`extract_email_features_from_text()` in `app.py` creates eight features:

| Feature | Meaning |
|---|---|
| `num_words` | Number of word-like tokens in the email. |
| `num_unique_words` | Number of distinct lowercased words. |
| `num_stopwords` | Count of common English stopwords. |
| `num_links` | Number of HTTP/WWW links. |
| `num_unique_domains` | Number of distinct link domains. |
| `num_email_addresses` | Number of email-address patterns. |
| `num_spelling_errors` | Simple heuristic count of abnormal word patterns. |
| `num_urgent_keywords` | Count of known urgent phishing phrases. |

Urgent phrases include examples such as `account suspended`, `verify password`, `final warning`, `security threat`, and `unauthorized login`.

The spelling feature is intentionally lightweight. It detects triple repeated characters or unusually long consonant-heavy words; it is not a complete spelling or grammar checker.

### Email false-positive tuning

To reduce legitimate emails being flagged as phishing, training evaluates every combination of class weights `1`, `3`, `5`, and `10` with decision thresholds `0.50`, `0.55`, `0.60`, `0.65`, and `0.70` on the validation set. It selects the configuration with the strongest phishing F1-score among candidates whose legitimate-email false-positive rate is at most 0.5%; if none meets that limit, it selects the best F1/precision/false-positive-rate trade-off. The final model is then retrained on the combined training and validation data and evaluated once on the untouched test set.

## 9. Hybrid late fusion

When both a URL and email are available, Phishimon combines their phishing probabilities:

```text
hybrid_phishing_score = (0.60 x URL phishing probability)
                      + (0.40 x Email phishing probability)
```

The final result is `PHISHING` when the combined score is at least 50%. URL evidence has the higher weight because the URL component is the stronger and more directly actionable signal in this prototype.

When only one input is supplied, the hybrid code normalizes the available weight and returns the available component's result.

## 10. Flask API

Run the service with:

```powershell
python app.py
```

The local server listens on `http://127.0.0.1:5000`.

### Endpoints

| Method and endpoint | Input | Purpose |
|---|---|---|
| `GET /api/health` | None | Checks whether the service is running. |
| `POST /api/predict/url` | `{ "url": "..." }` | Classifies a URL. |
| `POST /api/predict/email` | `{ "email_text": "..." }` or a feature object | Classifies email content. |
| `POST /api/predict/hybrid` | URL, email text, or both | Produces a combined result. |

### Sample URL request

```json
POST /api/predict/url
{
  "url": "https://example.com"
}
```

### Typical response fields

```json
{
  "status": "success",
  "prediction": "LEGITIMATE",
  "confidence": 96.4,
  "probability_legitimate": 96.4,
  "probability_phishing": 3.6
}
```

## 11. Chrome extension workflow

### 11.1 Background worker

`extension/background.js` runs in the background. It:

1. watches for completed tab navigation;
2. ignores browser-internal URLs such as `chrome://`;
3. sends a URL to `/api/predict/url`;
4. caches results for repeated URLs; and
5. sets `SAFE` or `RISK` on the extension badge.

### 11.2 Popup

The popup has two modes:

- **Active Page**: scans the current tab and displays probabilities.
- **Manual Scanner**: accepts a custom URL, email body, or both and requests hybrid analysis.

### 11.3 Content script

`extension/content.js` runs on normal webpages. If a phishing result is returned, it injects a visible red warning banner. It also observes selected Gmail, Outlook, and Yahoo Mail message containers, extracts available email text and links, and requests hybrid analysis.

## 12. Model caching and reproducibility

The `models/` folder stores joblib files containing:

- the trained model;
- the exact feature list;
- an artifact version; and
- the important training configuration;
- the validation-selected email threshold and selection metrics.

`MODEL_ARTIFACT_VERSION` is used to prevent the application from silently loading models created with older code or different settings. After a configuration change, the next application startup retrains the old model artifact.

## 13. Research workflow and evaluation

The project documentation reports experiments using accuracy, precision, recall, F1-score, ROC-AUC, and PR-AUC where appropriate.

### Why accuracy is not enough

Phishing datasets are commonly imbalanced: legitimate examples outnumber phishing examples. A model can therefore obtain a high accuracy by predicting most records as legitimate while missing many attacks.

- **Precision**: Of all inputs predicted as phishing, how many were really phishing?
- **Recall**: Of all phishing inputs, how many were detected?
- **F1-score**: A balance between precision and recall.
- **ROC-AUC**: A threshold-independent measure of URL classifier discrimination.
- **PR-AUC**: Especially useful when phishing examples are rare, as in the email dataset.

Research-support scripts under `scratch/` include ROC-curve and SHAP-plot generation. SHAP is used to rank the relative contribution of features to a model's output. It explains model behavior; it does not prove that a particular feature causes phishing.

## 14. How to run the project

1. Install the Python dependencies used by the code: Flask, flask-cors, pandas, NumPy, scikit-learn, XGBoost, and joblib.
2. Keep the datasets in the project root.
3. Start the server with `python app.py`.
4. In Chrome, open `chrome://extensions`.
5. Enable **Developer mode**.
6. Choose **Load unpacked** and select the `extension` folder.
7. Open a page, click the Phishimon extension icon, and inspect the result.

The first server run after a model configuration update can take longer because the models are retrained and cached.

## 15. Testing checklist

- `GET /api/health` returns an `ok` status.
- A normal public URL returns a valid JSON prediction.
- A URL containing suspicious credential-related terms can be scanned.
- A normal email text returns extracted features and a result.
- A suspicious email text with urgent language and links can be scanned.
- A hybrid request returns URL, email, and combined fields where both inputs exist.
- Browser-internal tabs are ignored.
- When the API is offline, the extension does not incorrectly show a safety decision.
- A phishing result produces a visible warning banner.

## 16. Important limitations

- The model is only as reliable as its training data and chosen features.
- A high test score does not guarantee performance against every new real-world phishing campaign.
- The email model is a lightweight engineered-feature baseline, not a semantic language-understanding system.
- The URL and email datasets are independent, so the late-fusion design has not been evaluated as a paired multimodal benchmark.
- The current API is local (`127.0.0.1`) and intended for prototype use. A production system requires authentication, secure deployment, data-retention controls, threat-intelligence integration, and continuous evaluation.

## 17. Future improvements

- Use newer and more diverse datasets from multiple time periods.
- Add email headers, sender reputation, attachment analysis, and domain-age information.
- Use HTML and webpage visual features in addition to URL text.
- Add multilingual phishing analysis.
- Evaluate the hybrid score using paired email-and-URL data.
- Calibrate thresholds using operational false-positive and false-negative costs.
- Present SHAP-style explanations in the user interface.

## 18. Short explanation for a demonstration

> Phishimon is a browser-based phishing-detection prototype. It uses XGBoost models to analyse URL patterns and email-content indicators. The Flask API returns phishing probabilities, and the Chrome extension turns those probabilities into SAFE or RISK warnings. When an email contains a suspicious link, the system combines URL and email evidence using a weighted hybrid score.
