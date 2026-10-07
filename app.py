import streamlit as st
import re
from urllib.parse import urlparse
import datetime

# Page Configuration
st.set_page_config(
    page_title="SOC-Console | Phishing Scam & Fraud Detection", 
    page_icon="🛡️", 
    layout="centered"
)

# Simple Header
st.markdown("### 🛡️ ScamGuard - Phishing & Fraud Detection Console")
st.markdown("<p style='font-size: 13px; color: #888;'>Local Heuristic Threat Analysis & Security Awareness Engine</p>", unsafe_allow_html=True)
st.markdown("---")

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

# ---------------- UI TABS ----------------
tab1, tab2, tab3 = st.tabs(["🔍 Threat Scan", "🔗 URL Inspector", "🧠 Phishing Awareness Quiz"])

with tab1:
    st.subheader("Message & Email Threat Scanner")
    user_msg = st.text_area("Paste suspicious message or email body:", height=120, placeholder="Type or paste text here...")
    
    if st.button("Run Threat Scan"):
        if not user_msg.strip():
            st.warning("Please enter text to scan.")
        else:
            with st.spinner("Analyzing text..."):
                report = analyze_message_heuristics(user_msg)
                st.markdown("### Analysis Report")
                st.markdown(report)
                
                st.download_button(
                    label="📥 Download Incident Report",
                    data=report,
                    file_name=f"threat_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

with tab2:
    st.subheader("URL Phishing Inspector")
    url_input = st.text_input("Enter URL to inspect:", placeholder="https://instagramm.com")
    
    if st.button("Inspect URL"):
        if not url_input.strip():
            st.warning("Please enter a URL to inspect.")
        else:
            with st.spinner("Analyzing URL..."):
                report = analyze_url_heuristics(url_input)
                st.markdown("### URL Report")
                st.markdown(report)
                
                st.download_button(
                    label="📥 Download Incident Report",
                    data=report,
                    file_name=f"url_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

with tab3:
    st.subheader("Security Awareness & Phishing Quiz")
    st.markdown("Test your ability to spot social engineering tactics and deceptive URLs.")
    
    score_tracker = 0
    
    # Question 1
    st.markdown("**Q1: You receive an SMS stating your bank account is suspended and demanding you click a link to verify credentials immediately. What should you do?**")
    q1 = st.radio("Choose an option:", ["Click the link quickly to fix it", "Ignore the link and check your official banking app/website directly", "Forward the message to friends"], key="q1")
    
    # Question 2
    st.markdown("**Q2: Which of the following URLs shows signs of typosquatting/brand impersonation?**")
    q2 = st.radio("Choose an option:", ["https://www.netflix.com/login", "https://netflix-secure-billing-update.com/signin", "https://help.netflix.com"], key="q2")
    
    # Question 3
    st.markdown("**Q3: What is the primary psychological trigger used in advance-fee or lottery winning scams?**")
    q3 = st.radio("Choose an option:", ["Fear and panic", "Greed and excitement over unexpected wealth", "Curiosity about a package delivery"], key="q3")
    
    if st.button("Submit Quiz Answers"):
        correct_count = 0
        if q1 == "Ignore the link and check your official banking app/website directly":
            correct_count += 1
        if q2 == "https://netflix-secure-billing-update.com/signin":
            correct_count += 1
        if q3 == "Greed and excitement over unexpected wealth":
            correct_count += 1
            
        st.markdown("---")
        st.markdown(f"### 📊 Your Results: {correct_count} / 3 Correct")
        if correct_count == 3:
            st.success("🎉 Excellent! You have strong security awareness and can effectively recognize phishing red flags.")
        elif correct_count >= 1:
            st.info("👍 Good effort! Review common social engineering patterns to sharpen your defense skills.")
        else:
            st.warning("⚠️ Keep practicing! Be cautious of urgent alerts and lookalike domains.")
