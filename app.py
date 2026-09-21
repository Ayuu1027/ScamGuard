import streamlit as st
import pandas as pd
import datetime
from urllib.parse import urlparse
import re

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
st.sidebar.text_input("Security Token / Node ID", type="password", placeholder="NODE-SECURE-ID")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 System Telemetry")
st.sidebar.info("Neural Defense Engine: **OPERATIONAL**\n\nMode: **HEURISTIC PATTERN MATCHING**\n\nDatabase: **LOCAL VECTOR KERNEL**")

# ---------------- MANUAL HEURISTIC DEFENSE ENGINE ----------------
FRAUD_SIGNALS = {
    "Financial & Payment Urgency": ["wire transfer", "bank account", "routing number", "gift card", "bitcoin", "crypto", "western union", "overdue invoice", "suspended"],
    "Credential Harvesting": ["password", "login", "verify identity", "ssn", "social security", "otp", "one-time password", "credentials", "sign-in"],
    "Advance-Fee / Prizes": ["inheritance", "million dollars", "lottery", "claim prize", "beneficiary", "unclaimed", "processing fee"],
    "Aggressive Pressure Tactics": ["immediate action", "act now", "final notice", "legal action", "within 24 hours", "compromised", "failure to comply"]
}

def analyze_message_heuristics(message):
    text = message.lower()
    matched_categories = {}
    total_score = 0
    
    for category, keywords in FRAUD_SIGNALS.items():
        hits = [kw for kw in keywords if kw in text]
        if hits:
            matched_categories[category] = hits
            total_score += len(hits) * 20

    exclamation_count = text.count("!")
    total_score += min(exclamation_count * 5, 20)
    total_score = min(total_score, 100)

    if total_score >= 60:
        risk_level = "High"
        verdict = "Malicious Scam / Phishing"
        intent = "Credential theft, unauthorized financial transfer, or social engineering fraud."
    elif total_score >= 25:
        risk_level = "Medium"
        verdict = "Suspicious Communication"
        intent = "Potential phishing attempt utilizing social pressure or urgency patterns."
    elif total_score > 0:
        risk_level = "Low"
        verdict = "Potential Warning Signs"
        intent = "Mild trigger patterns observed; exercise standard operational caution."
    else:
        risk_level = "None"
        verdict = "Safe / Legitimate Context"
        intent = "No malicious heuristics or threat signatures detected."

    tactics = list(matched_categories.keys()) if matched_categories else ["None identified"]
    
    report = f"""
- **Verdict**: {verdict}
- **Risk Level**: {risk_level} (Calculated Score: {total_score}/100)
- **Attacker Intent**: {intent}
- **Manipulation Tactics**: {', '.join(tactics)}
- **Recommended Action**: {"Isolate session, block sender, and report to SOC security team immediately." if total_score >= 25 else "No immediate threat indicators present. Standard communication protocol applies."}
    """
    return report

def analyze_url_heuristics(url):
    if not url.startswith("http"): 
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    reasons = []
    score = 0

    famous_brands = ["instagram", "facebook", "whatsapp", "google", "netflix", "paypal", "microsoft", "apple", "amazon"]
    for brand in famous_brands:
        if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
            score += 50
            reasons.append(f"Typosquatting or brand spoofing detected for target entity: '{brand}'")

    if len(url) > 75:
        score += 20
        reasons.append(f"Abnormally long URL string ({len(url)} characters)")
    if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', url):
        score += 30
        reasons.append("Direct IP address substitution used instead of valid domain name")
    if "@" in url:
        score += 25
        reasons.append("Contains '@' symbol syntax obfuscation")
    if parsed.scheme == "http":
        score += 15
        reasons.append("Insecure HTTP protocol transmission")

    score = min(100, score)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low" if score > 0 else "None"
    verdict = "Malicious / Phishing" if score >= 40 else "Legitimate Domain"
    
    analysis_text = f"Evaluated domain structure and spelling anomalies against standard security matrices."
    if reasons:
        analysis_text = "Structure contains structural anomalies or lookalike character changes mimicking legitimate services."

    report = f"""
- **Verdict**: {verdict}
- **Risk Level**: {level} (Score: {score}/100)
- **Target Brand (if impersonated)**: {reasons[0].split("'")[1] if "spoofing detected for target entity" in ' '.join(reasons) else "None"}
- **Threat Analysis**: {analysis_text}
- **Detected Indicators**:
  {'\n  '.join([f'- ⚠️ {r}' for r in reasons]) if reasons else '- No structural anomalies or spoofing flags identified.'}
- **Recommended Action**: {"Do not click or input credentials. Terminate connection immediately." if score >= 40 else "URL structure appears normal. Proceed with standard caution."}
    """
    return report

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
    st.markdown('<div class="metric-container"><div class="metric-val">0.0s</div><div class="metric-lbl">Local Latency</div></div>', unsafe_allow_html=True)
with col_m4:
    st.markdown('<div class="metric-container"><div class="metric-val">ONLINE</div><div class="metric-lbl">Engine Status</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Main Navigation Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🗂 Scan History"])

with tab1:
    st.markdown("### 📥 Inbound Message & Email Threat Scanner")
    st.markdown("<p style='font-size:12px; color:#6b8a80;'>Feed raw email content or SMS text for heuristic signature extraction and behavioral risk classification.</p>", unsafe_allow_html=True)
    
    user_msg = st.text_area("Message Body:", height=130, placeholder="Paste suspicious message, notice, or email content here...")
    
    if st.button("▶ Execute Threat Scan"):
        if not user_msg.strip():
            st.warning("Please provide input text to analyze.")
        else:
            with st.spinner("Processing local heuristic behavioral vectors..."):
                analysis_result = analyze_message_heuristics(user_msg)
                
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
    st.markdown("<p style='font-size:12px; color:#6b8a80;'>Evaluate domains for typosquatting, obfuscation anomalies, and brand spoofing vectors locally.</p>", unsafe_allow_html=True)
    
    url_input = st.text_input("Target URL:", placeholder="https://instagramm.com")
    
    if st.button("Inspect URL Structure"):
        if not url_input.strip():
            st.warning("Please enter a target URL.")
        else:
            with st.spinner("Deconstructing domain syntax and token patterns..."):
                url_analysis_result = analyze_url_heuristics(url_input)
                
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
