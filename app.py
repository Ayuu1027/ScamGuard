import streamlit as st
import datetime
import os
from urllib.parse import urlparse
import google.generativeai as genai

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
    </style>
    """, unsafe_allow_html=True)

inject_css()

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []

# Sidebar Configuration for Gemini API Key
st.sidebar.header("⚙️ Configuration")
gemini_api_key = st.secrets.get("GEMINI_API_KEY", "") or st.sidebar.text_input("Gemini API Key", type="password", placeholder="YOUR API KEY")

if gemini_api_key:
    genai.configure(api_key=gemini_api_key)

# ---------------- PURE GEMINI AI LOGIC ----------------
def analyze_with_gemini(email_body, api_key):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = f"""
        You are an expert Cybersecurity Operations Center (SOC) threat analyst. Analyze the following message text for phishing, social engineering, or fraud risks using your comprehensive global knowledge base. Do not rely on static rules; evaluate context, tone, and intent dynamically.
        
        Message: "{email_body}"
        
        Provide your response in this exact format:
        - Verdict: [Safe or Phishing / Malicious Scam]
        - Risk Level: [None, Low, Medium, or High]
        - Attacker Intent: [Brief description of what they are trying to achieve]
        - Manipulation Tactics: [Key social engineering strategies identified]
        - Recommended Action: [What the user should do immediately]
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error communicating with Gemini API: {str(e)}"

# URL Structural Checks (Structural checks, not hardcoded content text dictionaries)
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
    if parsed.scheme == "http":
        score += 10; reasons.append("Insecure HTTP protocol")

    score = min(100, score)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low" if score > 0 else "None"
    return {"url": url, "score": score, "risk_level": level, "reasons": reasons}

# ---------------- UI LAYOUT ----------------
st.markdown("""
<div class="term-banner">
    <div class="term-title">🛡️ ScamGuard - Phishing Scam & Fraud Detection</div>
    <div class="term-sub">SOC Console v3.0 | Dynamic LLM Defense Engine: ONLINE</div>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🗂 Scan History"])

with tab1:
    st.subheader("Message & Email Threat Scanner")
    user_msg = st.text_area("Paste suspicious message or email body:", height=140, placeholder="Type or paste any text message, email, or suspicious notification here...")
    
    if st.button("▶ Run Threat Scan"):
        if not user_msg.strip():
            st.warning("Please enter text to scan.")
        elif not gemini_api_key:
            st.warning("⚠️ Please provide your Gemini API Key in the sidebar or Streamlit secrets to run the threat engine.")
        else:
            with st.spinner("Consulting Gemini global threat intelligence database..."):
                ai_response = analyze_with_gemini(user_msg, gemini_api_key)
                
                st.subheader("📊 Threat Analysis Report")
                st.markdown(ai_response)
                
                # Log history
                st.session_state.history.append({
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": " Text Scan",
                    "preview": user_msg[:30] + "..."
                })

with tab2:
    st.subheader("Dedicated URL Phishing Analyzer")
    url_input = st.text_input("Enter URL to inspect:", placeholder="https://example.com/login")
    if st.button("Inspect URL"):
        if url_input.strip():
            res = analyze_url_detailed(url_input)
            st.markdown(f"**Structural Risk Level:** `{res['risk_level']}` (Score: {res['score']}/100)")
            if res['reasons']:
                st.write("**Detected Structural Anomalies:**")
                for r in res['reasons']:
                    st.markdown(f"- ⚠️ {r}")
            else:
                st.success("No structural anomalies found.")

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
