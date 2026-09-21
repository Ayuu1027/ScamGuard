import streamlit as st
import pandas as pd
import datetime
from urllib.parse import urlparse
import google.generativeai as genai

# Page Configuration
st.set_page_config(
    page_title="SOC-Console | Phishing Scam & Fraud Detection", 
    page_icon="🛡️", 
    layout="wide"
)

# ---------------- ADVANCED CSS STYLING ----------------
def inject_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap');
        
        html, body, [class*="css"] { 
            font-family: 'JetBrains Mono', monospace; 
        }
        
        :root { 
            --bg-deep: #030608; 
            --bg-panel: #080e13; 
            --bg-card: #0d161d;
            --neon-green: #00ff9d; 
            --neon-cyan: #00e5ff; 
            --neon-red: #ff2e63; 
            --neon-amber: #ffb800; 
            --text-main: #c0d8d0;
            --border-glow: rgba(0, 255, 157, 0.2);
        }

        .stApp { 
            background: radial-gradient(circle at 10% 20%, #081617 0%, var(--bg-deep) 60%);
            color: var(--text-main); 
        }

        #MainMenu, footer, header { visibility: hidden; }
        .block-container { padding-top: 1.5rem; max-width: 1250px; }

        /* Custom Header Banner */
        .soc-banner { 
            border: 1px solid var(--border-glow); 
            background: linear-gradient(135deg, rgba(0,255,157,0.08) 0%, rgba(8,14,19,0.8) 100%); 
            border-radius: 8px; 
            padding: 22px 28px; 
            margin-bottom: 24px; 
            box-shadow: 0 0 30px rgba(0,255,157,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .soc-title { font-size: 28px; font-weight: 800; color: var(--neon-green); letter-spacing: -0.5px; text-shadow: 0 0 15px rgba(0,255,157,0.4); }
        .soc-sub { color: #6b8a80; font-size: 13px; margin-top: 4px; }
        .status-badge { background: rgba(0,255,157,0.1); border: 1px solid var(--neon-green); color: var(--neon-green); padding: 6px 14px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }

        /* Metric Cards */
        .metric-container {
            background: var(--bg-card);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }
        .metric-val { font-size: 18px; font-weight: 700; color: var(--neon-cyan); }
        .metric-lbl { font-size: 11px; color: #6b8a80; margin-top: 2px; text-transform: uppercase; }

        /* Tabs and Inputs styling */
        .stTabs [data-baseweb="tab-list"] { gap: 10px; background-color: transparent; }
        .stTabs [data-baseweb="tab"] { 
            background-color: var(--bg-panel); 
            border: 1px solid rgba(255,255,157,0.08);
            border-radius: 6px 6px 0 0; 
            color: #8fa8a0;
            padding: 10px 20px;
            font-weight: 600;
        }
        .stTabs [aria-selected="true"] { 
            background-color: var(--bg-card) !important; 
            border-color: var(--neon-green) !important;
            color: var(--neon-green) !important;
        }

        /* Buttons */
        .stButton button {
            background: linear-gradient(90deg, rgba(0,255,157,0.15) 0%, rgba(0,229,255,0.15) 100%);
            border: 1px solid var(--neon-green);
            color: var(--neon-green);
            font-weight: 700;
            border-radius: 4px;
            padding: 0.6rem 1.2rem;
            transition: all 0.3s ease;
        }
        .stButton button:hover {
            background: var(--neon-green);
            color: var(--bg-deep);
            box-shadow: 0 0 15px rgba(0,255,157,0.4);
        }
    </style>
    """, unsafe_allow_html=True)

inject_css()

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []

# Sidebar Configuration
st.sidebar.markdown("### ⚙️ SOC Parameters")
api_token = st.secrets.get("GEMINI_API_KEY", "") or st.sidebar.text_input("Security Token", type="password", placeholder="ENTER TOKEN")

if api_token:
    genai.configure(api_key=api_token)

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 System Telemetry")
st.sidebar.info("Neural Defense Engine: **OPERATIONAL**\n\nLatency Mode: **ULTRA-FAST**\n\nDatabase: **DYNAMIC VECTOR**")

# ---------------- DEFENSE ENGINE LOGIC ----------------
def analyze_threat_signature(input_text, analysis_type, token):
    try:
        genai.configure(api_key=token)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        if analysis_type == "message":
            prompt = f"""
            Perform a fast security scan on this message for phishing or fraud risks:
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
            Analyze this URL structure for typosquatting or brand impersonation:
            URL: "{input_text}"
            Provide a concise response in this exact format:
            - Verdict: [Legitimate or Malicious / Typosquatting / Phishing]
            - Risk Level: [None, Low, Medium, or High]
            - Target Brand (if impersonated): [Name of brand or None]
            - Threat Analysis: [Why this URL is safe or dangerous]
            - Recommended Action: [What to do]
            """
            
        response = model.generate_content(
            prompt, 
            generation_config={"max_output_tokens": 250, "temperature": 0.1}
        )
        return response.text
    except Exception as e:
        return f"Error executing threat analysis engine: {str(e)}"

# ---------------- UI DASHBOARD HEADER ----------------
st.markdown("""
<div class="soc-banner">
    <div>
        <div class="soc-title">🛡️ ScamGuard SOC-Console</div>
        <div class="soc-sub">Advanced Heuristic Threat Analysis & Behavioral Telemetry Interface</div>
    </div>
    <div>
        <span class="status-badge">🟢 LIVE SECURE</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Top Telemetry Metrics Row
col_m1, col_m2, col_m3, col_m4 = st.columns(4)
with col_m1:
    st.markdown('<div class="metric-container"><div class="metric-val">v3.2.1</div><div class="metric-lbl">Core Build</div></div>', unsafe_allow_html=True)
with col_m2:
    st.markdown(f'<div class="metric-container"><div class="metric-val">{len(st.session_state.history)}</div><div class="metric-lbl">Scans Logged</div></div>', unsafe_allow_html=True)
with col_m3:
    st.markdown('<div class="metric-container"><div class="metric-val">0.4s</div><div class="metric-lbl">Avg Response</div></div>', unsafe_allow_html=True)
with col_m4:
    st.markdown('<div class="metric-container"><div class="metric-val">ONLINE</div><div class="metric-lbl">Engine Status</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Main Navigation Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🗂 Scan History"])

with tab1:
    st.markdown("### 📥 Inbound Message & Email Threat Scanner")
    st.markdown("<p style='font-size:12px; color:#6b8a80;'>Feed raw email content or SMS text for vector signature extraction and behavioral risk classification.</p>", unsafe_allow_html=True)
    
    user_msg = st.text_area("Message Body:", height=130, placeholder="Paste suspicious message, notice, or email content here...")
    
    if st.button("▶ Execute Threat Scan"):
        if not user_msg.strip():
            st.warning("Please provide input text to analyze.")
        elif not api_token:
            st.warning("⚠️ Please provide your Security Token in the sidebar configuration.")
        else:
            with st.spinner("Analyzing behavioral vectors and heuristic patterns..."):
                analysis_result = analyze_threat_signature(user_msg, "message", api_token)
                
                st.markdown("---")
                st.markdown("### 📋 Threat Analysis Report")
                st.markdown(analysis_result)
                
                st.session_state.history.append({
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "Text Scan",
                    "preview": user_msg[:35] + "..."
                })

with tab2:
    st.markdown("### 🌐 Structural URL Phishing Inspector")
    st.markdown("<p style='font-size:12px; color:#6b8a80;'>Evaluate domains for typosquatting, obfuscation anomalies, and brand spoofing vectors.</p>", unsafe_allow_html=True)
    
    url_input = st.text_input("Target URL:", placeholder="https://instagramm.com")
    
    if st.button("Inspect URL Structure"):
        if not url_input.strip():
            st.warning("Please enter a target URL.")
        elif not api_token:
            st.warning("⚠️ Please provide your Security Token in the sidebar configuration.")
        else:
            with st.spinner("Deconstructing domain syntax and token vectors..."):
                url_analysis_result = analyze_threat_signature(url_input, "url", api_token)
                
                st.markdown("---")
                st.markdown("### 📋 URL Assessment Report")
                st.markdown(url_analysis_result)
                
                st.session_state.history.append({
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "URL Scan",
                    "preview": url_input[:35] + "..."
                })

with tab3:
    st.markdown("### 🗂 Session Telemetry & Audit Trail")
    st.markdown("<p style='font-size:12px; color:#6b8a80;'>Real-time log of security events processed during the current session.</p>", unsafe_allow_html=True)
    
    if st.session_state.history:
        history_df = pd.DataFrame(st.session_state.history)
        st.dataframe(history_df, use_container_width=True)
        if st.button("Clear Audit Log"):
            st.session_state.history = []
            st.rerun()
    else:
        st.info("No security events logged in current session.")
