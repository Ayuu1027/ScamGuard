import streamlit as st
import pandas as pd
import datetime
from urllib.parse import urlparse
import google.generativeai as genai

st.set_page_config(
    page_title="SOC-Console | Phishing Scam & Fraud Detection", 
    page_icon="🛡️", 
    layout="wide"
)

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

if "history" not in st.session_state:
    st.session_state.history = []

st.sidebar.header("⚙️ Configuration")
api_token = st.secrets.get("GEMINI_API_KEY", "") or st.sidebar.text_input("Security Token", type="password", placeholder="ENTER TOKEN")

if api_token:
    genai.configure(api_key=api_token)

def analyze_threat_signature(input_text, analysis_type, token):
    try:
        genai.configure(api_key=token)
        # Using the fast low-latency production model identifier
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        if analysis_type == "message":
            prompt = f"""
            Perform a fast heuristic and behavioral analysis on this message for phishing or fraud risks:
            Message: "{input_text}"
            Provide a concise response in this exact format:
            - Verdict: [Safe or Phishing / Malicious Scam]
            - Risk Level: [None, Low, Medium, or High]
            - Attacker Intent: [Brief description]
            - Manipulation Tactics: [Key strategies]
            - Recommended Action: [What to do]
            """
        else:
            prompt = f"""
            Analyze this URL structure for typosquatting, brand impersonation, or phishing indicators:
            URL: "{input_text}"
            Provide a concise response in this exact format:
            - Verdict: [Legitimate or Malicious / Typosquatting / Phishing]
            - Risk Level: [None, Low, Medium, or High]
            - Target Brand (if impersonated): [Name of brand or None]
            - Threat Analysis: [Why this URL is safe or dangerous based on its structure and domain spelling]
            - Recommended Action: [What the user should do]
            """
            
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error executing threat analysis engine: {str(e)}"

st.markdown("""
<div class="term-banner">
    <div class="term-title">🛡️ ScamGuard - Phishing Scam & Fraud Detection</div>
    <div class="term-sub">SOC Console v3.2 | Neural Defense Engine: ONLINE</div>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🗂 Scan History"])

with tab1:
    st.subheader("Message & Email Threat Scanner")
    user_msg = st.text_area("Paste suspicious message or email body:", height=140, placeholder="Type or paste any text message, email, or suspicious notification here...")
    
    if st.button("▶ Run Threat Scan"):
        if not user_msg.strip():
            st.warning("Please enter text to scan.")
        elif not api_token:
            st.warning("⚠️ Please provide your security token in the sidebar configuration.")
        else:
            with st.spinner("Executing threat heuristic analysis..."):
                analysis_result = analyze_threat_signature(user_msg, "message", api_token)
                
                st.subheader("📊 Threat Analysis Report")
                st.markdown(analysis_result)
                
                st.session_state.history.append({
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "Text Scan",
                    "preview": user_msg[:30] + "..."
                })

with tab2:
    st.subheader("URL Phishing Inspector")
    url_input = st.text_input("Enter URL to inspect:", placeholder="https://instagramm.com")
    
    if st.button("Inspect URL"):
        if not url_input.strip():
            st.warning("Please enter a URL to inspect.")
        elif not api_token:
            st.warning("⚠️ Please provide your security token in the sidebar configuration.")
        else:
            with st.spinner("Analyzing domain structure and typosquatting vectors..."):
                url_analysis_result = analyze_threat_signature(url_input, "url", api_token)
                
                st.subheader("📊 URL Analysis Report")
                st.markdown(url_analysis_result)
                
                st.session_state.history.append({
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "URL Scan",
                    "preview": url_input[:30] + "..."
                })

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
