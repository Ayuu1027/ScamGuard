import streamlit as st
import re
from urllib.parse import urlparse
import datetime

# Page Configuration
st.set_page_config(
    page_title="SOC-Console | Phishing Scam & Fraud Detection", 
    page_icon="🛡️", 
    layout="wide"
)

# ---------------- PROFESSIONAL CLEAN STYLING ----------------
def inject_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        html, body, [class*="css"] { 
            font-family: 'Inter', sans-serif; 
            color: #1e293b;
        }
        
        :root { 
            --bg-app: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --primary: #0284c7;
            --border-color: #cbd5e1;
        }

        .stApp { 
            background-color: var(--bg-app);
            color: var(--text-main); 
        }

        #MainMenu, footer, header { visibility: hidden; }
        .block-container { padding-top: 2rem; max-width: 1100px; }

        /* Professional Header Banner */
        .soc-banner { 
            border: 1px solid var(--border-color); 
            background: var(--bg-card); 
            border-radius: 8px; 
            padding: 24px 30px; 
            margin-bottom: 24px; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .soc-title { font-size: 24px; font-weight: 700; color: #0f172a; letter-spacing: -0.5px; }
        .soc-sub { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
        .status-badge { background: #e0f2fe; border: 1px solid #bae6fd; color: #0369a1; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }

        /* Fix text color visibility across elements */
        p, span, label, div, .stMarkdown {
            color: #1e293b !important;
        }
        
        .stRadio label p {
            color: #1e293b !important;
            font-weight: 500;
        }

        /* Tabs styling */
        .stTabs [data-baseweb="tab-list"] { gap: 8px; background-color: transparent; }
        .stTabs [data-baseweb="tab"] { 
            background-color: #e2e8f0; 
            border: none;
            border-radius: 6px 6px 0 0; 
            color: #334155 !important;
            padding: 10px 20px;
            font-weight: 600;
        }
        .stTabs [aria-selected="true"] { 
            background-color: var(--bg-card) !important; 
            color: var(--primary) !important;
            box-shadow: 0 -2px 0 0 var(--primary);
        }

        /* Buttons */
        .stButton button {
            background-color: var(--primary);
            border: none;
            color: white !important;
            font-weight: 600;
            border-radius: 6px;
            padding: 0.5rem 1.2rem;
            transition: background 0.2s ease;
        }
        .stButton button:hover {
            background-color: #0369a1;
        }
    </style>
    """, unsafe_allow_html=True)

inject_css()

# ---------------- SIDEBAR DASHBOARD ----------------
st.sidebar.markdown("### ⚙️ SOC Control Panel")
st.sidebar.text_input("Node Security Token", type="password", placeholder="NODE-SECURE-KEY")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 System Telemetry")
st.sidebar.markdown(
    """
    - **Core Version:** v3.5.0
    - **Execution Mode:** Local Kernel
    - **Latency Overhead:** 0.0s
    - **Defense Status:** Active
    """,
    unsafe_allow_html=True
)
st.sidebar.markdown("---")
st.sidebar.info("Operational Status: **SECURE**\n\nHeuristic Engine running locally without external API dependencies.")

# ---------------- MANUAL HEURISTIC ENGINE ----------------
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
        intent = "Mild trigger patterns observed; exercise caution."
    else:
        risk_level = "None"
        verdict = "Safe / Legitimate Context"
        intent = "No malicious heuristics detected."

    tactics = list(matched_categories.keys()) if matched_categories else ["None identified"]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""========================================
SCAMGUARD INCIDENT REPORT - MESSAGE SCAN
========================================
Timestamp: {timestamp}
Analyzed Text: {message[:120]}...

- Verdict: {verdict}
- Risk Level: {risk_level} (Score: {total_score}/100)
- Attacker Intent: {intent}
- Manipulation Tactics: {', '.join(tactics)}
- Recommended Action: {"Isolate session, block sender, and report immediately." if total_score >= 25 else "No immediate threat indicators present."}
========================================"""
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
            reasons.append(f"Typosquatting or brand spoofing detected for: '{brand}'")

    if len(url) > 75:
        score += 20
        reasons.append(f"Abnormally long URL string ({len(url)} characters)")
    if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', url):
        score += 30
        reasons.append("Direct IP address substitution used instead of domain name")
    if "@" in url:
        score += 25
        reasons.append("Contains '@' symbol syntax obfuscation")
    if parsed.scheme == "http":
        score += 15
        reasons.append("Insecure HTTP protocol transmission")

    score = min(100, score)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low" if score > 0 else "None"
    verdict = "Malicious / Phishing" if score >= 40 else "Legitimate Domain"
    
    analysis_text = "Evaluated domain structure and spelling anomalies."
    if reasons:
        analysis_text = "Structure contains lookalike character changes or structural anomalies."

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"""========================================
SCAMGUARD INCIDENT REPORT - URL INSPECTION
========================================
Timestamp: {timestamp}
Target URL: {url}

- Verdict: {verdict}
- Risk Level: {level} (Score: {score}/100)
- Threat Analysis: {analysis_text}
- Detected Indicators:
  {'\n  '.join([f'- ⚠️ {r}' for r in reasons]) if reasons else '- No structural anomalies or spoofing flags identified.'}
- Recommended Action: {"Do not click or input credentials. Terminate connection immediately." if score >= 40 else "URL structure appears normal."}
========================================"""
    return report

# ---------------- HEADER BANNER ----------------
st.markdown("""
<div class="soc-banner">
    <div>
        <div class="soc-title">🛡️ ScamGuard SOC-Console</div>
        <div class="soc-sub">Advanced Local Heuristic Threat Analysis & Behavioral Telemetry Interface</div>
    </div>
    <div>
        <span class="status-badge">🟢 SECURE KERNEL</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Main Navigation Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🧠 Phishing Awareness Quiz"])

with tab1:
    st.markdown("### Inbound Message & Email Threat Scanner")
    st.markdown("<p style='font-size:13px; color:#64748b;'>Evaluate raw email body content or SMS text payloads for heuristic signature extraction and social engineering risk scoring.</p>", unsafe_allow_html=True)
    
    user_msg = st.text_area("Message Body:", height=130, placeholder="Paste suspicious message, notice, or email content here...")
    
    if st.button("Execute Threat Scan"):
        if not user_msg.strip():
            st.warning("Please provide input text to analyze.")
        else:
            with st.spinner("Processing local heuristic behavioral vectors..."):
                report = analyze_message_heuristics(user_msg)
                
                st.markdown("---")
                st.markdown("### Threat Analysis Report")
                st.markdown(report)
                
                st.download_button(
                    label="Download Incident Report",
                    data=report,
                    file_name=f"threat_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

with tab2:
    st.markdown("### Structural URL Phishing Inspector")
    st.markdown("<p style='font-size:13px; color:#64748b;'>Deconstruct target domain parameters for typosquatting, syntax obfuscation, and brand spoofing vectors locally.</p>", unsafe_allow_html=True)
    
    url_input = st.text_input("Target URL:", placeholder="https://instagramm.com")
    
    if st.button("Inspect URL Structure"):
        if not url_input.strip():
            st.warning("Please enter a target URL.")
        else:
            with st.spinner("Deconstructing domain syntax and token patterns..."):
                report = analyze_url_heuristics(url_input)
                
                st.markdown("---")
                st.markdown("### URL Assessment Report")
                st.markdown(report)
                
                st.download_button(
                    label="Download Incident Report",
                    data=report,
                    file_name=f"url_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

with tab3:
    st.markdown("### Security Awareness & Phishing Quiz (10 Questions)")
    st.markdown("<p style='font-size:13px; color:#64748b;'>Interactive security assessment module testing foundational knowledge of social engineering and fraud vectors.</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    q1 = st.radio("Q1: You receive an SMS stating your bank account is suspended and demanding you click a link to verify credentials immediately. What should you do?", ["Click the link quickly to fix it", "Ignore the link and check your official banking app/website directly", "Forward the message to friends"], index=None, key="q1")
    
    q2 = st.radio("Q2: Which of the following URLs shows signs of typosquatting/brand impersonation?", ["https://www.netflix.com/login", "https://netflix-secure-billing-update.com/signin", "https://help.netflix.com"], index=None, key="q2")
    
    q3 = st.radio("Q3: What is the primary psychological trigger used in advance-fee or lottery winning scams?", ["Fear and panic", "Greed and excitement over unexpected wealth", "Curiosity about a package delivery"], index=None, key="q3")

    q4 = st.radio("Q4: What is 'Quishing'?", ["Quick password resets via SMS", "Phishing attacks conducted using malicious QR codes", "Quiet background listening malware"], index=None, key="q4")

    q5 = st.radio("Q5: Why might an email containing a raw IP address (e.g., http://192.168.1.50/login) instead of a domain name be suspicious?", ["It means the server is very fast", "Legitimate companies rarely host official login portals on raw internal IP addresses", "IP addresses are immune to phishing"], index=None, key="q5")

    q6 = st.radio("Q6: What does SPF (Sender Policy Framework) help protect against?", ["Email header spoofing and unauthorized senders", "Computer viruses hidden in PDF attachments", "Slow internet connection speeds"], index=None, key="q6")

    q7 = st.radio("Q7: You receive an email from your 'CEO' asking you to urgently purchase gift cards for a client meeting and send the codes. What is this scam type called?", ["SQL Injection", "CEO Fraud / Business Email Compromise (BEC)", "Cross-Site Scripting"], index=None, key="q7")

    q8 = st.radio("Q8: Which file extension combination is a classic indicator of a hidden malicious executable payload?", ["document.pdf", "invoice.pdf.exe", "spreadsheet.xlsx"], index=None, key="q8")

    q9 = st.radio("Q9: What does HTTPS provide that HTTP does not?", ["Guaranteed safety from all phishing websites", "Encrypted data transmission between your browser and the server", "Faster page loading times"], index=None, key="q9")

    q10 = st.radio("Q10: If a trusted friend's social media account sends you a strange link saying 'Look who died in this video!', what is the most likely cause?", ["Your friend personally checked the video", "Your friend's account has been compromised by malware or credential theft", "It is an official memorial notification"], index=None, key="q10")
    
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Submit Quiz Assessment"):
        answers = [q1, q2, q3, q4, q5, q6, q7, q8, q9, q10]
        if any(ans is None for ans in answers):
            st.warning("⚠️ Please answer all 10 questions before submitting your assessment.")
        else:
            correct_count = 0
            if q1 == "Ignore the link and check your official banking app/website directly": correct_count += 1
            if q2 == "https://netflix-secure-billing-update.com/signin": correct_count += 1
            if q3 == "Greed and excitement over unexpected wealth": correct_count += 1
            if q4 == "Phishing attacks conducted using malicious QR codes": correct_count += 1
            if q5 == "Legitimate companies rarely host official login portals on raw internal IP addresses": correct_count += 1
            if q6 == "Email header spoofing and unauthorized senders": correct_count += 1
            if q7 == "CEO Fraud / Business Email Compromise (BEC)": correct_count += 1
            if q8 == "invoice.pdf.exe": correct_count += 1
            if q9 == "Encrypted data transmission between your browser and the server": correct_count += 1
            if q10 == "Your friend's account has been compromised by malware or credential theft": correct_count += 1
                
            st.markdown("---")
            st.markdown(f"### 📊 Final Evaluation Score: {correct_count} / 10 Correct")
            if correct_count >= 9:
                st.success("🏆 Outstanding! You have professional-level security awareness and threat detection skills.")
            elif correct_count >= 6:
                st.info("👍 Good job! You have a solid grasp of core cybersecurity principles with minor room for review.")
            else:
                st.warning("⚠️ Keep practicing! Review common phishing indicators and social engineering tactics to strengthen your defense knowledge.")
