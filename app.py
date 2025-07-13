# app.py

import streamlit as st
import numpy as np
import tldextract
import re
import math
import time
import requests
import socket
import joblib
import whois
import ssl
import certifi
import tensorflow as tf
import cloudpickle
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tensorflow.keras.models import load_model

# -------------------------------
# 📦 Load models and scaler
# -------------------------------
# Load scaler
with open("scaler.pkl", "rb") as f:
    scaler = cloudpickle.load(f)

# Load models
cnn_model = load_model("cnn_model.keras")
lstm_model = load_model("lstm_model.keras")
meta_model = load_model("meta_model.keras")

# Load XGBoost (cloudpickle)
with open("xgb_model.pkl", "rb") as f:
    xgb_model = cloudpickle.load(f)

# -------------------------------
# 🔧 Utility Functions
# -------------------------------
def get_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return -sum([p * math.log(p, 2) for p in prob]) if prob else 0

def is_ip(domain):
    try:
        socket.inet_aton(domain)
        return True
    except:
        return False

def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
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

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return int((time.time() - creation.timestamp()) / 86400)
    except:
        return -1

def check_ssl_certificate(url):
    try:
        hostname = urlparse(url).hostname
        ctx = ssl.create_default_context(cafile=certifi.where())
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            s.getpeercert()
        return True
    except:
        return False

def get_page_info(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.title.string.strip() if soup.title else "No Title"
        text = soup.get_text().lower()
        keywords = ["login", "verify", "account", "secure", "password", "update", "signin", "security"]
        flag = int(any(k in text for k in keywords))
        return flag, title, len(r.history)
    except:
        return 0, "Not Reachable", 0

# -------------------------------
# 🚀 Streamlit App
# -------------------------------
st.set_page_config(page_title="Phishing Detection", layout="centered")
st.title("🔍 Real-Time Phishing Detection App")
st.markdown("Paste a URL below to check if it's **legit**, **suspicious**, or **phishing**.")

url = st.text_input("🔗 Enter URL:")
if st.button("Analyze URL"):
    if not url:
        st.warning("⚠️ Please enter a URL to analyze.")
    else:
        with st.spinner("Analyzing..."):
            parsed = urlparse(url)
            domain = parsed.hostname
            uses_https = url.lower().startswith("https://")
            ip_used = is_ip(domain)
            ssl_ok = check_ssl_certificate(url)
            domain_age = get_domain_age(domain)
            content_flag, page_title, redirects = get_page_info(url)

            features = extract_features(url)
            if features is None:
                st.error("❌ Feature extraction failed.")
                st.stop()

            scaled = scaler.transform(features)
            cnn_input = scaled.reshape(scaled.shape[0], scaled.shape[1], 1)
            lstm_input = scaled.reshape(scaled.shape[0], 1, scaled.shape[1])

            cnn_pred = cnn_model.predict(cnn_input, verbose=0)[0][0]
            lstm_pred = lstm_model.predict(lstm_input, verbose=0)[0][0]
            xgb_pred = xgb_model.predict_proba(scaled)[0][1]

            meta_input = np.array([[cnn_pred, lstm_pred, xgb_pred]])
            final_pred = meta_model.predict(meta_input, verbose=0)[0][0]
            confidence = round(final_pred * 100, 2)

            if final_pred >= 0.7:
                verdict = "🛑 Phishing"
                explanation = "This site strongly resembles a phishing site."
            elif 0.4 <= final_pred < 0.7 or domain_age < 30 or content_flag:
                verdict = "⚠️ Suspicious"
                explanation = "Some signs of phishing detected. Be cautious."
            else:
                verdict = "✅ Legitimate"
                explanation = "The system believes this site is safe."

            # Output
            st.subheader("📋 Result")
            st.write(f"📆 Domain Age: `{domain_age} days`")
            st.write(f"🔐 HTTPS: {'✅' if uses_https else '❌'}")
            st.write(f"🔐 SSL Certificate: {'✅' if ssl_ok else '❌'}")
            st.write(f"🌐 IP Used: {'✅' if ip_used else '❌'}")
            st.write(f"🔁 Redirects: `{redirects}`")
            st.write(f"🧠 Page Title: `{page_title}`")
            st.write(f"🔍 Content Scan: `{'Suspicious' if content_flag else 'Clean'}`")

            st.markdown("---")
            st.write(f"📊 CNN Confidence: **{cnn_pred * 100:.2f}%**")
            st.write(f"📊 LSTM Confidence: **{lstm_pred * 100:.2f}%**")
            st.write(f"📊 XGBoost Confidence: **{xgb_pred * 100:.2f}%**")

            st.markdown("## 🧠 Final Verdict")
            st.success(f"{verdict} — Confidence: **{confidence}%**")
            st.markdown(f"💬 _Explanation_: {explanation}")
