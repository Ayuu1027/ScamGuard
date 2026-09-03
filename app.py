import pandas as pd
import numpy as np
import re
import streamlit as st
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib
from urllib.parse import urlparse
import datetime
import os
import google.generativeai as genai

# NLTK Setup
import nltk
try:
    from nltk.corpus import stopwords
    STOPWORDS = set(stopwords.words("english"))
except:
    nltk.download('stopwords')
    from nltk.corpus import stopwords
    STOPWORDS = set(stopwords.words("english"))

# Page Configuration
st.set_page_config(
    page_title="SOC-Console | Phishing Scam & Fraud Detection", 
    page_icon="🛡️", 
    layout="wide"
)

# ---------------- CSS STYLING ----------------
def inject_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        html, body, [class*="css"] { font-family: 'JetBrains Mono', monospace; }
        :root { --bg-deep:#05080a; --bg-panel:#0b1116; --bg-panel-2:#0e161c; --neon-green:#00ff9d; --neon-cyan:#00e5ff; --neon-red:#ff2e63; --neon-amber:#ffb800; --grid-line: rgba(0, 255, 157, 0.07); }
        .stApp { background: linear-gradient(var(--grid-line) 1px, transparent 1px), linear-gradient(90deg, var(--grid-line) 1px, transparent 1px), radial-gradient(circle at 15% 0%, #0d2620 0%, var(--bg-deep) 45%), var(--bg-deep); background-size: 34px 34px, 34px 34px, 100% 100%, 100%; color: #c0d8d0; }
        #MainMenu, footer, header {visibility: hidden;}
        .block-container { padding-top: 1.2rem; max-width: 1200px; }
        .term-banner { border: 1px solid rgba(0,255,157,0.35); background: linear-gradient(180deg, rgba(0,255,157,0.06), rgba(0,0,0,0)); border-radius: 6px; padding: 18px 22px; margin-bottom: 18px; box-shadow: 0 0 25px rgba(0,255,157,0.08); }
        .term-title { font-size: 26px; font-weight: 800; color: var(--neon-green); text-shadow: 0 0 12px rgba(0,255,157,0.5); }
        .term-sub { color: #6b8a80; font-size: 12px; margin-top: 4px; }
        .pill { font-size: 11px; padding: 4px 10px; border-radius: 3px; border: 1px solid rgba(0,255,157,0.3); color: var(--neon-green); background: rgba(0,255,157,0.05); }
    </style>
    """, unsafe_allow_html=True)

inject_css()

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []

# Sidebar Configuration for Gemini API Key
st.sidebar.header("⚙️ Configuration")
gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password", placeholder="YOUR API KEY")

# ---------------- LOGIC ----------------
def clean_email_body(email_body):
    email_body = re.sub(r'[^a-zA-Z\s]', '', email_body)
    email_body = ' '.join([word.lower() for word in email_body.split() if word.lower() not in STOPWORDS])
    return email_body

FRAUD_SIGNAL_CATEGORIES = {
    "Advance-Fee / Inheritance Scam": ["inheritance", "next of kin", "unclaimed fund", "beneficiary", "estate of", "million dollars", "lottery winner", "claim your prize", "processing fee", "diplomatic courier"],
    "Financial / Payment Urgency": ["wire transfer", "bank account", "routing number", "gift card", "bitcoin", "crypto wallet", "western union", "urgent payment", "overdue invoice", "account suspended", "verify your account"],
    "Credential Harvesting": ["social security number", "ssn", "date of birth", "login credentials", "confirm your password", "verify your identity", "otp code", "one time password"],
    "Pressure Tactics": ["act now", "immediate action required", "final notice", "legal action", "within 24 hours", "failure to comply", "account has been compromised"],
}

def extract_fraud_signals(email_body):
    text = email_body.lower()
    matched = {}
    total_hits = 0
    for cat, kws in FRAUD_SIGNAL_CATEGORIES.items():
        hits = [kw for kw in kws if kw in text]
        if hits:
            matched[cat] = hits
            total_hits += len(hits)
    exclamation_density = text.count('!') / max(len(text.split()), 1)
    currency_mentions = len(re.findall(r'(\$|usd|inr|₹|€|eur)\s?\d', text))
    score = min(100, (total_hits * 12) + (currency_mentions * 8) + (exclamation_density * 100))
    if score >= 60: level = "High"
    elif score >= 25: level = "Medium"
    elif score > 0: level = "Low"
    else: level = "None"
    return {"score": round(score, 1), "risk_level": level, "categories": matched, "currency_mentions": currency_mentions}

def analyze_with_gemini(email_body, api_key):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"""
        You are an expert Cybersecurity Operations Center (SOC) analyst. Analyze the following message text for phishing, social engineering, or fraud risks:
        
        "{email_body}"
        
        Provide a concise threat breakdown detailing:
        1. Intent / Objective of the attacker
        2. Key manipulation or social engineering tactics used
        3. Recommended action for the user
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error communicating with Gemini API: {str(e)}"

# Load or Train Model
@st.cache_resource
def load_or_train_model():
    if os.path.exists('phishing_model.pkl'):
        return joblib.load('phishing_model.pkl')
    else:
        default_texts = [
            "Congratulations you won a lottery claim your prize now",
            "Urgent bank account suspended verify credentials immediately",
            "Hey let's catch up for meeting tomorrow afternoon",
            "Please find attached project report for review"
        ]
        default_labels = [1, 1, 0, 0]
        df = pd.DataFrame({'email_body': default_texts, 'label': default_labels})
        df['cleaned_body'] = df['email_body'].apply(clean_email_body)
        model = make_pipeline(CountVectorizer(), MultinomialNB())
        model.fit(df['cleaned_body'], df['label'])
        joblib.dump(model, 'phishing_model.pkl')
        return model

model = load_or_train_model()

# URL Checker Logic
SHORTENERS = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly"]
SUSPICIOUS_KEYWORDS = ["login","secure","account","webscr","signin","banking","confirm","update"]

def analyze_url_detailed(url):
    if not url.startswith("http"): url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    reasons = []
    score = 0

    if len(url) > 75:
        score += 20; reasons.append(f"Very long URL ({len(url)} chars)")
    if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', url):
        score += 25; reasons.append("Uses IP address instead of domain name")
    if "@" in url:
        score += 20; reasons.append("Contains '@' symbol obfuscation")
    if any(s in domain for s in SHORTENERS):
        score += 15; reasons.append("URL shortener detected")
    if parsed.scheme == "http":
        score += 10; reasons.append("Insecure HTTP protocol")
    if any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS):
        score += 15; reasons.append("Contains sensitive keywords (login/secure)")

    score = min(100, score)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low" if score > 0 else "None"
    return {"url": url, "score": score, "risk_level": level, "reasons": reasons}

# ---------------- UI LAYOUT ----------------
st.markdown("""
<div class="term-banner">
    <div class="term-title">🛡ScamGuard - Phishing Scam & Fraud Detection </div>
    <div class="term-sub">SOC Console v2.4 | System Status: ONLINE | Active Defense Enabled</div>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🗂 Scan History"])

with tab1:
    st.subheader("Email & Message Threat Scanner")
    email_input = st.text_area("Paste email or message body:", height=140, placeholder="Congratulations! You've won a $1000 gift card...")
    
    if st.button("▶ Run Threat Scan"):
        if not email_input.strip():
            st.warning("Please enter text to scan.")
        else:
            cleaned = clean_email_body(email_input)
            pred = model.predict([cleaned])[0]
            verdict = "Phishing / Malicious" if pred == 1 else "Safe"
            
            fraud_data = extract_fraud_signals(email_input)
            
            st.markdown(f"**ML Verdict:** `{verdict}`")
            
            if fraud_data['categories']:
                st.write("**Matched Social Engineering Categories:**")
                for cat, kws in fraud_data['categories'].items():
                    st.markdown(f"- **{cat}**: {', '.join(kws)}")
            
            # Gemini LLM Deep Analysis Section
            if gemini_api_key:
                st.markdown("---")
                st.subheader("🧠 Gemini AI Deep Threat Intelligence")
                with st.spinner("Analyzing message context with Gemini API..."):
                    gemini_analysis = analyze_with_gemini(email_input, gemini_api_key)
                    st.write(gemini_analysis)
            else:
                st.info("💡 Tip: Enter your Gemini API key in the sidebar configuration to unlock advanced AI-powered threat analysis.")
            
            # Log history
            st.session_state.history.append({
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "Email Scan",
                "verdict": verdict,
                "risk": fraud_data['risk_level']
            })

with tab2:
    st.subheader("Dedicated URL Phishing Analyzer")
    url_input = st.text_input("Enter URL to inspect:", placeholder="https://example.com/login")
    if st.button("Inspect URL"):
        if url_input.strip():
            res = analyze_url_detailed(url_input)
            st.markdown(f"**Risk Level:** `{res['risk_level']}` (Score: {res['score']}/100)")
            if res['reasons']:
                st.write("**Detected Indicators:**")
                for r in res['reasons']:
                    st.markdown(f"- ⚠️ {r}")
            else:
                st.success("No malicious URL signatures found.")

with tab3:
    st.subheader("Session Scan History Log")
    if st.session_state.history:
        history_df = pd.DataFrame(st.session_state.history)
        st.dataframe(history_df, use_container_width=True)
        if st.button("Clear History"):
            st.session_state.history = []
            st.rerun()
    else:
        st.info("No scans recorded in current session yet.")
