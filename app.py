import re
from urllib.parse import urlparse

import joblib
import streamlit as st

from url_detector import analyze_url
from virustotal_checker import check_virustotal_url


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="ScamShield-PK",
    page_icon="🛡️",
    layout="centered"
)


# ---------------------------------------------------------
# LOAD MACHINE-LEARNING MODEL
# ---------------------------------------------------------

@st.cache_resource
def load_model():
    return joblib.load("scamshield_pk_ml_model.pkl")


ml_pipeline = load_model()


# ---------------------------------------------------------
# MESSAGE ANALYZER FUNCTIONS
# ---------------------------------------------------------

def detect_job_scam_evidence(text):
    text_lower = text.lower()
    evidence = []

    patterns = {
        "cnic_request": [
            r"\bcnic\b",
            r"cnic front",
            r"cnic back",
            r"شناختی کارڈ",
            r"شناختی"
        ],

        "otp_request": [
            r"\botp\b",
            r"one time password",
            r"verification code",
            r"code bhej"
        ],

        "fee_request": [
            r"\bfee\b",
            r"registration fee",
            r"verification fee",
            r"processing fee",
            r"send rs",
            r"easypaisa",
            r"jazzcash",
            r"فیس",
            r"رجسٹریشن فیس"
        ],

        "bank_details_request": [
            r"bank account",
            r"account number",
            r"bank details",
            r"iban",
            r"atm card",
            r"بینک اکاؤنٹ"
        ],

        "urgency": [
            r"\bimmediately\b",
            r"\btoday\b",
            r"\bnow\b",
            r"urgent",
            r"final warning",
            r"within \d+ minutes",
            r"foran",
            r"jaldi",
            r"abhi",
            r"فوری",
            r"ابھی"
        ],

        "whatsapp_only": [
            r"whatsapp only",
            r"contact on whatsapp",
            r"whatsapp par",
            r"whatsapp pe",
            r"whatsapp number",
            r"contact.*whatsapp"
        ],

        "unrealistic_salary": [
            r"earn rs\.?\s?\d+",
            r"weekly income",
            r"daily income",
            r"without experience",
            r"ghar beth",
            r"work from home.*\d+"
        ],

        "no_interview_claim": [
            r"without interview",
            r"no interview",
            r"bina interview",
            r"بغیر انٹرویو"
        ],

        "unverified_selection_claim": [
            r"congratulations.*selected",
            r"you are selected",
            r"appointment letter",
            r"selected for.*job",
            r"mubarak.*select",
            r"آپ منتخب ہو گئے"
        ],

        "official_process": [
            r"official career page",
            r"company website",
            r"online assessment",
            r"scheduled interview",
            r"apply through.*website",
            r"official email",
            r"company portal"
        ]
    }

    for label, pattern_list in patterns.items():
        if any(
            re.search(pattern, text_lower)
            for pattern in pattern_list
        ):
            evidence.append(label)

    return evidence


def analyze_job_message(text):
    evidence = detect_job_scam_evidence(text)

    probabilities = ml_pipeline.predict_proba([text])[0]
    class_names = list(ml_pipeline.classes_)

    scam_index = class_names.index("scam")
    ml_scam_probability = float(probabilities[scam_index])

    risk_score = ml_scam_probability

    high_risk_signals = {
        "cnic_request",
        "otp_request",
        "fee_request",
        "bank_details_request",
        "urgency"
    }

    suspicious_signals = {
        "whatsapp_only",
        "unrealistic_salary",
        "no_interview_claim",
        "unverified_selection_claim"
    }

    high_count = len(
        set(evidence) & high_risk_signals
    )

    suspicious_count = len(
        set(evidence) & suspicious_signals
    )

    if high_count >= 2:
        risk_score = max(risk_score, 0.90)

    elif high_count == 1:
        risk_score = max(risk_score, 0.70)

    elif suspicious_count >= 2:
        risk_score = max(risk_score, 0.60)

    elif suspicious_count == 1:
        risk_score = max(risk_score, 0.45)

    if (
        "official_process" in evidence
        and high_count == 0
    ):
        risk_score = min(risk_score, 0.34)

    risk_score = min(risk_score, 1.0)

    if risk_score >= 0.70:
        prediction = "SCAM"
        risk_level = "HIGH"

        action = (
            "Do not send money, CNIC, bank details, OTP, "
            "screenshots, or documents. Verify the vacancy "
            "through the employer's official career page."
        )

    elif risk_score >= 0.40:
        prediction = "SUSPICIOUS"
        risk_level = "MEDIUM"

        action = (
            "Do not share documents or money yet. Ask for "
            "the official vacancy link and verify it through "
            "the employer's official website."
        )

    else:
        prediction = "LEGITIMATE"
        risk_level = "LOW"

        action = (
            "No major scam signals were detected. Still "
            "verify the vacancy through the official company "
            "career page before sharing documents."
        )

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 2),
        "ml_scam_probability": round(
            ml_scam_probability,
            2
        ),
        "evidence": evidence,
        "recommended_action": action
    }


# ---------------------------------------------------------
# URL HELPER FUNCTIONS
# ---------------------------------------------------------

def normalize_url(url):
    """
    Add HTTPS when the user enters a URL without a scheme.
    """

    cleaned_url = url.strip()

    if not cleaned_url.lower().startswith(
        ("http://", "https://")
    ):
        cleaned_url = "https://" + cleaned_url

    return cleaned_url


def is_valid_url(url):
    """
    Perform basic URL validation before sending a request.
    """

    try:
        parsed = urlparse(url)

        return bool(
            parsed.scheme in {"http", "https"}
            and parsed.netloc
        )

    except ValueError:
        return False


def get_virustotal_api_key():
    """
    Safely read the API key from Streamlit Secrets.
    """

    try:
        return st.secrets.get(
            "VIRUSTOTAL_API_KEY",
            ""
        )

    except Exception:
        return ""


# ---------------------------------------------------------
# MAIN INTERFACE
# ---------------------------------------------------------

st.title("🛡️ ScamShield-PK")

st.write(
    "An academic AI-powered system for detecting suspicious "
    "job messages, phishing links and social-media lookalike URLs."
)

message_tab, url_tab = st.tabs(
    [
        "📩 Message Analyzer",
        "🔗 URL & Reputation Analyzer"
    ]
)


# ---------------------------------------------------------
# MESSAGE ANALYZER TAB
# ---------------------------------------------------------

with message_tab:

    st.subheader(
        "Job & Internship Scam Detection System"
    )

    st.write(
        "Paste a job, internship, WhatsApp, SMS or email "
        "message. The system combines machine learning with "
        "rule-based scam indicators."
    )

    message = st.text_area(
        "Paste job or internship message",
        height=180,
        placeholder=(
            "Example: Congratulations! You are selected. "
            "Send CNIC, OTP and Rs. 2,000 verification fee today."
        )
    )

    if st.button(
        "Analyze Message",
        type="primary",
        key="analyze_message_button"
    ):

        if not message.strip():
            st.warning(
                "Please paste a message first."
            )

        else:
            with st.spinner(
                "Analyzing message..."
            ):
                report = analyze_job_message(message)

            if report["risk_level"] == "HIGH":
                st.error(
                    f"🚨 Prediction: {report['prediction']} "
                    f"| Risk: {report['risk_level']}"
                )

            elif report["risk_level"] == "MEDIUM":
                st.warning(
                    f"⚠️ Prediction: {report['prediction']} "
                    f"| Risk: {report['risk_level']}"
                )

            else:
                st.success(
                    f"✅ Prediction: {report['prediction']} "
                    f"| Risk: {report['risk_level']}"
                )

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Hybrid Risk Score",
                    f"{report['risk_score']:.2f}"
                )

            with col2:
                st.metric(
                    "ML Scam Probability",
                    f"{report['ml_scam_probability']:.2f}"
                )

            st.progress(
                float(report["risk_score"])
            )

            st.write("### Detected evidence")

            if report["evidence"]:
                for evidence_item in report["evidence"]:
                    st.write(
                        f"• {evidence_item}"
                    )

            else:
                st.write(
                    "• No strong rule-based evidence detected"
                )

            st.info(
                report["recommended_action"]
            )


# ---------------------------------------------------------
# URL ANALYZER TAB
# ---------------------------------------------------------

with url_tab:

    st.subheader(
        "URL, Phishing & Social-Media Link Analyzer"
    )

    st.write(
        "Paste a website, Instagram, Facebook, LinkedIn, "
        "WhatsApp or Telegram link. The system checks its "
        "structure and optionally retrieves its existing "
        "VirusTotal reputation report."
    )

    url_input = st.text_input(
        "Enter website or social-media URL",
        placeholder=(
            "https://www.instagram.com/example/"
        ),
        key="url_input"
    )

    check_reputation = st.checkbox(
        "Also check VirusTotal reputation",
        value=True,
        help=(
            "The URL will be sent to VirusTotal to retrieve "
            "an existing security report."
        )
    )

    if st.button(
        "Analyze URL",
        type="primary",
        key="analyze_url_button"
    ):

        if not url_input.strip():
            st.warning(
                "Please enter a URL first."
            )

        else:
            normalized_url = normalize_url(
                url_input
            )

            if not is_valid_url(normalized_url):
                st.error(
                    "The entered URL is not valid. "
                    "Please enter a complete website link."
                )

            else:
                with st.spinner(
                    "Analyzing URL structure..."
                ):
                    url_report = analyze_url(
                        normalized_url
                    )

                risk_level = url_report.get(
                    "risk_level",
                    "UNKNOWN"
                )

                risk_score = float(
                    url_report.get(
                        "risk_score",
                        0.0
                    )
                )

                domain = url_report.get(
                    "domain",
                    ""
                )

                evidence = url_report.get(
                    "evidence",
                    []
                )

                platform = url_report.get(
                    "platform"
                )

                domain_status = url_report.get(
                    "domain_status",
                    "NOT_SOCIAL"
                )

                st.write("## Structural analysis")

                if risk_level == "HIGH":
                    st.error(
                        "🚨 HIGH-RISK URL STRUCTURE"
                    )

                elif risk_level == "MEDIUM":
                    st.warning(
                        "⚠️ SUSPICIOUS URL STRUCTURE"
                    )

                elif risk_level == "LOW":
                    st.success(
                        "✅ LOW STRUCTURAL RISK"
                    )

                else:
                    st.info(
                        "The structural risk could not "
                        "be determined."
                    )

                structural_col1, structural_col2 = (
                    st.columns(2)
                )

                with structural_col1:
                    st.metric(
                        "Structural Risk Score",
                        f"{risk_score:.2f}"
                    )

                with structural_col2:
                    st.metric(
                        "Structural Risk Level",
                        risk_level
                    )

                st.progress(
                    min(max(risk_score, 0.0), 1.0)
                )

                if domain:
                    st.write(
                        f"**Detected domain:** `{domain}`"
                    )

                if platform:
                    st.write(
                        f"**Detected platform:** {platform}"
                    )

                    if domain_status == "OFFICIAL":
                        st.success(
                            f"The link uses an official "
                            f"{platform} domain."
                        )

                    elif domain_status == "LOOKALIKE":
                        st.error(
                            f"The domain may be imitating "
                            f"{platform}."
                        )

                st.write(
                    "### Structural evidence"
                )

                for item in evidence:
                    st.write(f"• {item}")

                if risk_level == "HIGH":
                    st.error(
                        "Do not open this URL or enter personal "
                        "information. Verify the link through "
                        "the organization's official website."
                    )

                elif risk_level == "MEDIUM":
                    st.warning(
                        "Carefully verify the domain and sender "
                        "before opening this link."
                    )

                else:
                    st.info(
                        "No major structural warning signs were "
                        "detected. This does not guarantee that "
                        "the website, profile or account is genuine."
                    )

                # ---------------------------------------------
                # VIRUSTOTAL REPUTATION CHECK
                # ---------------------------------------------

                if check_reputation:

                    st.divider()

                    st.write(
                        "## VirusTotal reputation"
                    )

                    api_key = get_virustotal_api_key()

                    if not api_key:
                        st.warning(
                            "VirusTotal checking is unavailable "
                            "because the API key is missing from "
                            "Streamlit Secrets."
                        )

                    else:
                        with st.spinner(
                            "Checking VirusTotal database..."
                        ):
                            vt_report = (
                                check_virustotal_url(
                                    normalized_url,
                                    api_key
                                )
                            )

                        vt_status = vt_report.get(
                            "status"
                        )

                        if vt_status == "success":

                            vt_level = vt_report.get(
                                "reputation_level",
                                "UNKNOWN"
                            )

                            malicious = int(
                                vt_report.get(
                                    "malicious",
                                    0
                                )
                            )

                            suspicious = int(
                                vt_report.get(
                                    "suspicious",
                                    0
                                )
                            )

                            harmless = int(
                                vt_report.get(
                                    "harmless",
                                    0
                                )
                            )

                            undetected = int(
                                vt_report.get(
                                    "undetected",
                                    0
                                )
                            )

                            total_engines = int(
                                vt_report.get(
                                    "total_engines",
                                    0
                                )
                            )

                            if vt_level == "HIGH":
                                st.error(
                                    "🚨 VirusTotal reputation: "
                                    "HIGH RISK"
                                )

                            elif vt_level == "MEDIUM":
                                st.warning(
                                    "⚠️ VirusTotal reputation: "
                                    "SUSPICIOUS"
                                )

                            else:
                                st.success(
                                    "✅ VirusTotal reputation: "
                                    "LOW DETECTION"
                                )

                            vt_col1, vt_col2 = (
                                st.columns(2)
                            )

                            with vt_col1:
                                st.metric(
                                    "Malicious detections",
                                    malicious
                                )

                                st.metric(
                                    "Harmless detections",
                                    harmless
                                )

                            with vt_col2:
                                st.metric(
                                    "Suspicious detections",
                                    suspicious
                                )

                                st.metric(
                                    "Undetected",
                                    undetected
                                )

                            st.write(
                                f"**Total reporting engines:** "
                                f"{total_engines}"
                            )

                            if malicious > 0:
                                st.error(
                                    "One or more security engines "
                                    "flagged this URL as malicious. "
                                    "Avoid opening it."
                                )

                            elif suspicious > 0:
                                st.warning(
                                    "Some security engines marked "
                                    "this URL as suspicious. Proceed "
                                    "only after independent verification."
                                )

                            else:
                                st.info(
                                    "No malicious detections appeared "
                                    "in the retrieved report. This is "
                                    "not a guarantee that the link is safe."
                                )

                        elif vt_status == "not_found":
                            st.info(
                                vt_report.get(
                                    "message",
                                    "No existing VirusTotal report "
                                    "was found for this exact URL."
                                )
                            )

                            st.caption(
                                "ScamShield-PK currently retrieves "
                                "existing reports and does not submit "
                                "unknown URLs for a new scan."
                            )

                        else:
                            st.warning(
                                vt_report.get(
                                    "message",
                                    "VirusTotal checking could not "
                                    "be completed."
                                )
                            )


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.divider()

st.caption(
    "Academic prototype — results are risk estimates, not "
    "guarantees. Always verify messages, profiles and links "
    "through official organizational sources."
)

st.caption(
    "Privacy notice: when VirusTotal checking is enabled, "
    "the entered URL is sent to VirusTotal. Do not check "
    "private, password-reset or token-containing links."
)
