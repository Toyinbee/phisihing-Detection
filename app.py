# ---------------------------------------------
# ✅ Phishing Detection Streamlit App (app.py)
# ---------------------------------------------
import streamlit as st
import numpy as np
import tldextract
import re
import math
import time
import requests
import socket
import whois
import ssl
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import joblib
import tensorflow as tf
from xgboost import XGBClassifier

# ----------------------------
# 🔧 Feature Extraction Utils
# ----------------------------
def get_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob]) if prob else 0

def is_ip(domain):
    try:
        socket.inet_aton(domain)
        return True
    except:
        return False

def has_valid_ssl(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except:
        return False

def get_domain_age_days(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (time.time() - creation.timestamp()) / 86400 if creation else 0
        return int(age)
    except:
        return 0

def check_content_for_keywords(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code != 200:
            return 0, "No content"
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text().lower()
        keywords = ["login", "verify", "account", "secure", "password", "update", "signin", "security"]
        return int(any(k in text for k in keywords)), soup.title.string.strip() if soup.title else "No Title"
    except:
        return 0, "Not reachable"

def extract_features_from_url(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        extracted_info = tldextract.extract(url)
        subdomain = extracted_info.subdomain
        domain_name = extracted_info.domain
        suffix = extracted_info.suffix
        domain_part = subdomain if subdomain else ""
        subdomains = subdomain.split(".") if subdomain else []
        special_chars = r"[-_@=$!%*#?&]"

        return np.array([[
            len(url), url.count("."), int(bool(re.search(r"(\d)\1{1,}", url))), len(re.findall(r"\d", url)),
            len(re.findall(special_chars, url)), url.count("-"), url.count("_"), url.count("/"),
            url.count("?"), url.count("="), url.count("@"), url.count("$"), url.count("!"),
            url.count("#"), url.count("%"), len(domain), domain.count("."), domain.count("-"),
            int(bool(re.search(special_chars, domain))), len(re.findall(special_chars, domain)),
            int(bool(re.search(r"\d", domain))), len(re.findall(r"\d", domain)),
            int(bool(re.search(r"(\d)\1{1,}", domain))), len(subdomains), int("." in domain_part),
            int("-" in domain_part), sum(len(s) for s in subdomains)/len(subdomains) if subdomains else 0,
            sum(s.count(".") for s in subdomains)/len(subdomains) if subdomains else 0,
            sum(s.count("-") for s in subdomains)/len(subdomains) if subdomains else 0,
            int(any(re.search(special_chars, s) for s in subdomains)),
            sum(len(re.findall(special_chars, s)) for s in subdomains),
            int(any(char.isdigit() for char in domain_part)),
            sum(char.isdigit() for char in domain_part),
            int(bool(re.search(r"(\d)\1{1,}", domain_part))),
            int(bool(path)), len(path), int(bool(parsed.query)), int(bool(parsed.fragment)),
            int("#" in url), get_entropy(url), get_entropy(domain)
        ]])
    except:
        return None

# ----------------------------
# 🚀 Load Models & Scaler
# ----------------------------
scaler = joblib.load("scaler.pkl")
cnn_model = tf.keras.models.load_model("cnn_model.keras")
lstm_model = tf.keras.models.load_model("lstm_model.keras")
xgb_model = joblib.load("xgb_model.pkl")
meta_model = tf.keras.models.load_model("meta_model.keras")

# ----------------------------
# 🎯 Streamlit App Interface
# ----------------------------
st.title("🔐 Real-Time Phishing URL Detection")
url = st.text_input("🔗 Enter a URL to check:")

if st.button("Analyze"):
    if not url:
        st.warning("Please enter a valid URL to proceed.")
    else:
        st.info("Analyzing... Please wait.")
        start = time.time()

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        uses_https = url.lower().startswith("https://")
        domain_age = get_domain_age_days(domain)
        has_ssl = has_valid_ssl(url)
        is_ip_used = is_ip(domain)
        redirects = 0

        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            redirects = len(r.history)
        except:
            st.warning("⚠️ Domain may not resolve or is inactive.")

        content_flag, page_title = check_content_for_keywords(url)
        features = extract_features_from_url(url)

        if features is None:
            st.error("❌ Could not extract features from the URL.")
        else:
            features_scaled = scaler.transform(features)
            cnn_input = features_scaled.reshape(features_scaled.shape[0], features_scaled.shape[1], 1)
            lstm_input = features_scaled.reshape(features_scaled.shape[0], 1, features_scaled.shape[1])

            cnn_pred = cnn_model.predict(cnn_input, verbose=0)[0][0]
            lstm_pred = lstm_model.predict(lstm_input, verbose=0)[0][0]
            xgb_pred = xgb_model.predict_proba(features_scaled)[0][1]

            meta_input = np.array([[cnn_pred, lstm_pred, xgb_pred]])
            final_pred = meta_model.predict(meta_input, verbose=0)[0][0]
            percent_confidence = round(final_pred * 100, 2)

            if final_pred >= 0.7:
                verdict = "🛑 Phishing"
                explanation = "⚠️ This site strongly resembles a phishing site."
            elif 0.4 <= final_pred < 0.7 or domain_age < 30 or content_flag:
                verdict = "⚠️ Suspicious"
                explanation = "⚠️ This site shows red flags such as a new domain, suspicious content, or unclear security."
            else:
                verdict = "✅ Legitimate"
                explanation = "✅ This site appears safe based on the analysis."

            st.markdown("""
            ### 🧠 Scan Summary
            """)
            st.write(f"📆 Domain Age: `{domain_age} days`")
            st.write(f"🔐 HTTPS: {'✅ Yes' if uses_https else '❌ No'}")
            st.write(f"🔐 SSL Certificate: {'✅ Valid' if has_ssl else '❌ Not Found'}")
            st.write(f"🌐 Uses IP Address: {'✅ Yes' if is_ip_used else '❌ No'}")
            st.write(f"🔁 Redirects: `{redirects}`")
            st.write(f"🧠 Page Title: `{page_title}`")
            st.write(f"🔍 Content Scan: {'⚠️ Suspicious' if content_flag else '✅ Clean'}")

            st.markdown("""
            ### 🤖 Model Confidence
            """)
            st.write(f"📊 CNN Confidence: `CNN {cnn_pred * 100:.2f}% phishing`")
            st.write(f"📊 LSTM Confidence: `LSTM {lstm_pred * 100:.2f}% phishing`")
            st.write(f"📊 XGBoost Confidence: `XGBoost {xgb_pred * 100:.2f}% phishing`")

            st.markdown("""
            ### 🧾 Final Verdict
            """)
            st.write(f"🧠 Final Verdict: `{verdict}`")
            st.write(f"🔎 Confidence Score: `{percent_confidence}%`")
            st.success(explanation)
            st.write(f"⏱ Detection Time: `{round(time.time() - start, 3)} seconds`")

            if cnn_pred > 0.99 and lstm_pred < 0.2 and xgb_pred < 0.3:
                st.warning("🚨 CNN is highly confident, but other models are not. Please review manually.")
