import streamlit as st
import re
import tldextract

st.set_page_config(page_title="Phishing URL Detector", page_icon="🔐", layout="centered", initial_sidebar_state="expanded")

# Light theme CSS (same as your code, omitted here for brevity)
st.markdown("""
<style>
/* your CSS here */
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='text-align: center; color:#4A90E2;'>🔐 Phishing URL Detector</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size:18px; color:#555555;'>Check if a URL is suspicious or safe</p>", unsafe_allow_html=True)
st.markdown("---")

with st.sidebar:
    st.header("ℹ️ How does this work?")
    st.markdown("""
    This tool checks for **warning signs** in URLs that are common in phishing attempts:
    - 🔢 **URL Length**: URLs longer than 75 characters are suspicious.
    - 🌐 **IP Address**: Using an IP address instead of domain name is risky.
    - 📧 **@ Symbol**: Can be used to mislead users.
    - ➖ **Hyphen (-)**: Rare in legitimate domain names.
    - 🔒 **HTTPS**: Lack of HTTPS means insecure connection.
    - 🟠 **Dot Count**: Too many dots can indicate deception.
    
    Scoring system:
    - ✅ Score < 2 → Likely Safe  
    - ⚠️ Score 2-3 → Suspicious  
    - 🚫 Score ≥ 4 → Likely Phishing
    
    **Stay vigilant & don’t share personal info on suspicious sites!**
    """)

url = st.text_input("🔗 Enter URL", placeholder="https://secure.example.com", help="Paste any full URL to analyze").strip()

def has_ip_address(url):
    ip_pattern = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    return re.search(ip_pattern, url) is not None

def check_url_features(url):
    features = {}
    features["URL Length"] = len(url)
    features["Contains IP"] = has_ip_address(url)
    features["Contains '@'"] = "@" in url
    try:
        domain = tldextract.extract(url).domain
        features["Has Dash (-)"] = "-" in domain
    except Exception:
        features["Has Dash (-)"] = False
    features["Uses HTTPS"] = url.startswith("https")
    features["Dot Count"] = url.count(".")
    return features

def evaluate_phishing(features):
    score = 0
    if features["URL Length"] > 75: score += 1
    if features["Contains IP"]: score += 2
    if features["Contains '@'"]: score += 1
    if features["Has Dash (-)"]: score += 1
    if not features["Uses HTTPS"]: score += 1
    if features["Dot Count"] > 5: score += 1

    if score >= 4:
        return "⚠️ Likely Phishing", "danger"
    elif 2 <= score < 4:
        return "⚠️ Suspicious", "warning"
    else:
        return "✅ Likely Safe", "success"

if url:
    st.markdown("---")
    features = check_url_features(url)
    result, level = evaluate_phishing(features)

    st.markdown("### 🔍 URL Analysis")
    with st.expander("Click to view extracted features"):
        st.table(features)

    st.markdown("### 🧠 Prediction Result")
    st.markdown(f"<div class='result-box'>{result}</div>", unsafe_allow_html=True)

    if level == "danger":
        st.error("🚫 This URL looks **very suspicious**. Do not trust or click it.")
    elif level == "warning":
        st.warning("⚠️ This URL looks a bit **suspicious**. Proceed with caution.")
    else:
        st.success("✅ This URL looks **safe**. No red flags found.")
