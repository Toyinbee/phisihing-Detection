import streamlit as st
import numpy as np
import pandas as pd
import tldextract
import re
import math
import time
import requests
import socket
import os
import whois
import ssl
import certifi
import tensorflow as tf
import xgboost as xgb
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from sklearn.preprocessing import StandardScaler
from scipy.stats import ks_2samp
from tensorflow.keras.models import load_model

# -------------------------------
# 📦 Load Scaler and Models
# -------------------------------
scaler = StandardScaler()
params = np.load("scaler_params.npy", allow_pickle=True)
scaler.mean_, scaler.scale_ = params

xgb_model = xgb.XGBClassifier()
xgb_model.load_model("xgb_model.json")

cnn_model = load_model("cnn_model.h5", compile=False)
lstm_model = load_model("lstm_model.h5", compile=False)
meta_model = load_model("meta_model.h5", compile=False)

baseline_path = "data/baseline_features_sampled.npy"
baseline = np.load(baseline_path) if os.path.exists(baseline_path) else None

# -------------------------------
# 🔧 Utility Functions
# -------------------------------
def get_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(string)]
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
        subdomain = extracted.subdomain or ""
        domain_part = subdomain
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
st.title("\U0001F6E1\uFE0F Real-Time Phishing Detection App")
st.markdown("Paste a URL below to check whether it's Legitimate, Suspicious, or Phishing.")

url = st.text_input("\U0001F517 Paste URL here:")
if st.button("Analyze URL"):
    if not url:
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Analyzing..."):
            parsed = urlparse(url)
            domain = parsed.hostname
            https = url.lower().startswith("https://")
            ip_used = is_ip(domain)
            ssl_cert = check_ssl_certificate(url)
            domain_age = get_domain_age(domain)
            content_flag, page_title, redirects = get_page_info(url)

            features = extract_features(url)
            if features is None:
                st.error("❌ Failed to extract features.")
                st.stop()

            scaled = scaler.transform(features)

            if baseline is not None:
                try:
                    drift_flags = []
                    for i in range(scaled.shape[1]):
                        stat, p = ks_2samp(scaled[:, i], baseline[:, i])
                        drift_flags.append(p < 0.05)
                    if any(drift_flags):
                        st.warning("⚠️ Feature drift detected! Model may need retraining.")
                    else:
                        st.info("✅ No feature drift detected.")
                except Exception as e:
                    st.error(f"❌ Drift detection failed: {e}")
            else:
                st.info("ℹ️ Baseline not available. Skipping drift detection.")

            cnn_input = scaled.reshape(scaled.shape[0], scaled.shape[1], 1)
            lstm_input = scaled.reshape(scaled.shape[0], 1, scaled.shape[1])
            cnn_prob = cnn_model.predict(cnn_input, verbose=0)[0][0]
            lstm_prob = lstm_model.predict(lstm_input, verbose=0)[0][0]
            xgb_prob = xgb_model.predict_proba(scaled)[0][1]

            meta_input = np.array([[cnn_prob, lstm_prob, xgb_prob]])
            final_prob = meta_model.predict(meta_input, verbose=0)[0][0]
            phishing_conf = final_prob * 100
            legit_conf = 100 - phishing_conf

            st.subheader("📋 Analysis Summary")
            st.write(f"📆 Domain Age: `{domain_age} days`")
            st.write(f"🔐 HTTPS: {'✅' if https else '❌'}")
            st.write(f"🔐 SSL Certificate: {'✅' if ssl_cert else '❌'}")
            st.write(f"🌐 IP Used: {'✅' if ip_used else '❌'}")
            st.write(f"🔁 Redirects: `{redirects}`")
            st.write(f"🧠 Page Title: `{page_title}`")
            st.write(f"🔍 Content Keywords: `{'Suspicious' if content_flag else 'Clean'}`")

            st.markdown("---")
            st.markdown("### 📊 Model Confidence")
            st.write(f"🧠 CNN Model: **{cnn_prob * 100:.2f}% phishing** → **{100 - cnn_prob * 100:.2f}% safe**")
            st.write(f"🧠 LSTM Model: **{lstm_prob * 100:.2f}% phishing** → **{100 - lstm_prob * 100:.2f}% safe**")
            st.write(f"🧠 XGBoost Model: **{xgb_prob * 100:.2f}% phishing** → **{100 - xgb_prob * 100:.2f}% safe**")

            st.markdown("### 🧠 Final Verdict")
            if final_prob >= 0.7:
                st.error(f"🛑 Phishing — Model is **{phishing_conf:.2f}%** confident this site is malicious.")
                explanation = "This site strongly resembles a phishing website. Avoid entering sensitive information."
            elif 0.4 <= final_prob < 0.7 or domain_age < 30 or content_flag:
                st.warning(f"⚠️ Suspicious — Model is **{phishing_conf:.2f}%** confident this site may be phishing.")
                explanation = "Some red flags were detected. Proceed with caution."
            else:
                st.success(f"✅ Legitimate — Model is **{legit_conf:.2f}%** confident this site is safe.")
                explanation = "This website looks safe and clean based on the model’s analysis."

            st.markdown(f"💬 _Explanation_: {explanation}")

            st.session_state["prediction_made"] = True
            st.session_state["url"] = url
            st.session_state["features"] = features
            st.session_state["final_prob"] = float(final_prob)

if st.session_state.get("prediction_made"):
    st.markdown("### 📝 Help us improve!")
    user_feedback = st.radio("Was this prediction correct?", ("Yes", "No"), key="feedback")

    if st.button("Submit Feedback", key="submit_feedback"):
        label = 1 if st.session_state["final_prob"] >= 0.7 else 0
        correct = 1 if user_feedback == "Yes" else 0
        true_label = label if correct else int(not label)

        new_data = {
            "url": st.session_state["url"],
            "features": st.session_state["features"].flatten().tolist(),
            "model_prediction": st.session_state["final_prob"],
            "true_label": true_label
        }

        feedback_path = "data/new_data.csv"
        os.makedirs("data", exist_ok=True)

        try:
            if os.path.exists(feedback_path):
                df = pd.read_csv(feedback_path)
                df = pd.concat([df, pd.DataFrame([new_data])], ignore_index=True)
            else:
                df = pd.DataFrame([new_data])
            df.to_csv(feedback_path, index=False)
            st.success("✅ Feedback recorded! Thank you.")
        except Exception as e:
            st.error(f"❌ Could not save feedback: {e}")

# -------------------------------
# 👨‍💻 Developer Tools Section
# -------------------------------
st.sidebar.markdown("### 👨‍💻 Developer Tools")
dev_mode = st.sidebar.checkbox("Enable Developer Mode")

if dev_mode:
    st.markdown("### 🔧 Update XGBoost Model")
    if st.button("Update XGBoost"):
        try:
            update_path = "data/new_data.csv"
            if not os.path.exists(update_path):
                st.warning("⚠️ No new feedback data found.")
            else:
                df_update = pd.read_csv(update_path)
                X_new = np.array(df_update["features"].apply(eval).tolist())
                y_new = np.array(df_update["true_label"])
                X_new_scaled = scaler.transform(X_new)

                xgb_model.fit(X_new_scaled, y_new)
                xgb_model.save_model("xgb_model.json")
                st.success("✅ XGBoost model updated successfully!")
        except Exception as e:
            st.error(f"❌ Failed to update model: {e}")

    st.markdown("### 📥 Download Feedback Data")
    csv_path = "data/new_data.csv"
    if os.path.exists(csv_path):
        with open(csv_path, "rb") as f:
            st.download_button(
                label="📥 Download new_data.csv",
                data=f,
                file_name="new_data.csv",
                mime="text/csv"
    )
    else:
        st.info("ℹ️ No feedback data available yet.")
