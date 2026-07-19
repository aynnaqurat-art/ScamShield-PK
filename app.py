import streamlit as st
import joblib
import re

from url_detector import analyze_url


st.set_page_config(
    page_title="ScamShield-PK",
    page_icon="🛡️",
    layout="centered"
)


@st.cache_resource
def load_model():
    return joblib.load("scamshield_pk_ml_model.pkl")


ml_pipeline = load_model()


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
        if any(re.search(pattern, text_lower) for pattern in pattern_list):
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

    high_count = len(set(evidence) & high_risk_signals)
    suspicious_count = len(set(evidence) & suspicious_signals)

    if high_count >= 2:
        risk_score = max(risk_score, 0.90)

    elif high_count == 1:
        risk_score = max(risk_score, 0.70)

    elif suspicious_count >= 2:
        risk_score = max(risk_score, 0.60)

    elif suspicious_count == 1:
        risk_score = max(risk_score, 0.45)

    if "official_process" in evidence and high_count == 0:
        risk_score = min(risk_score, 0.34)

    risk_score = min(risk_score, 1.0)

    if risk_score >= 0.70:
        prediction = "SCAM"
        risk_level = "HIGH"

        action = (
            "Do not send money, CNIC, bank details, OTP, screenshots, "
            "or documents. Verify the vacancy from the employer's "
            "official career page."
        )

    elif risk_score >= 0.40:
        prediction = "SUSPICIOUS"
        risk_level = "MEDIUM"

        action = (
            "Do not share documents or money yet. Ask for the official "
            "vacancy link and verify it through the employer's official "
            "career page."
        )

    else:
        prediction = "LEGITIMATE"
        risk_level = "LOW"

        action = (
            "No major scam signals were detected. Still verify the "
            "vacancy through the official company career page before "
            "sharing documents."
        )

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 2),
        "ml_scam_probability": round(ml_scam_probability, 2),
        "evidence": evidence,
        "recommended_action": action
    }


st.title("🛡️ ScamShield-PK")

message_tab, url_tab = st.tabs(
    ["📩 Message Analyzer", "🔗 URL Analyzer"]
)


with message_tab:

    st.subheader("Job & Internship Scam Detection System")

    st.write(
        "Paste a job, internship, WhatsApp, SMS, or email message below. "
        "The system checks scam signals such as CNIC requests, OTP requests, "
        "fees, urgency, and fake selection claims."
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
            st.warning("Please paste a message first.")

        else:
            report = analyze_job_message(message)

            if report["risk_level"] == "HIGH":
                st.error(
                    f"Prediction: {report['prediction']} | "
                    f"Risk: {report['risk_level']}"
                )

            elif report["risk_level"] == "MEDIUM":
                st.warning(
                    f"Prediction: {report['prediction']} | "
                    f"Risk: {report['risk_level']}"
                )

            else:
                st.success(
                    f"Prediction: {report['prediction']} | "
                    f"Risk: {report['risk_level']}"
                )

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Risk Score",
                    f"{report['risk_score']:.2f}"
                )

            with col2:
                st.metric(
                    "ML Scam Probability",
                    f"{report['ml_scam_probability']:.2f}"
                )

            st.progress(report["risk_score"])

            evidence_text = (
                ", ".join(report["evidence"])
                if report["evidence"]
                else "No strong evidence detected"
            )

            st.write("**Detected evidence:**", evidence_text)
            st.info(report["recommended_action"])


with url_tab:

    st.subheader("Suspicious URL Analyzer")

    st.write(
        "Paste a website link below. The system will check the URL "
        "for structural scam and phishing indicators."
    )

    url_input = st.text_input(
        "Enter website URL",
        placeholder="https://example.com",
        key="url_input"
    )

    if st.button(
        "Analyze URL",
        type="primary",
        key="analyze_url_button"
    ):

        if not url_input.strip():
            st.warning("Please enter a URL first.")

        else:
            url_report = analyze_url(url_input)

            risk_level = url_report["risk_level"]
            risk_score = url_report["risk_score"]
            domain = url_report["domain"]
            evidence = url_report["evidence"]

            if risk_level == "HIGH":
                st.error("🚨 HIGH-RISK URL")

            elif risk_level == "MEDIUM":
                st.warning("⚠️ SUSPICIOUS URL")

            elif risk_level == "LOW":
                st.success("✅ LOW STRUCTURAL RISK")

            else:
                st.info("URL risk could not be determined.")

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "URL Risk Score",
                    f"{risk_score:.2f}"
                )

            with col2:
                st.metric(
                    "Risk Level",
                    risk_level
                )

            st.progress(risk_score)

            if domain:
                st.write(f"**Detected domain:** `{domain}`")

            st.write("**Detected URL evidence:**")

            for item in evidence:
                st.write(f"• {item}")

            if risk_level == "HIGH":
                st.error(
                    "Do not open this URL or enter personal information. "
                    "Verify the link through the organization's official website."
                )

            elif risk_level == "MEDIUM":
                st.warning(
                    "Open this URL only after carefully verifying the domain "
                    "and sender."
                )

            elif risk_level == "LOW":
                st.info(
                    "No major structural warning signs were detected. "
                    "However, this does not guarantee that the website is safe."
                )


st.caption(
    "Academic prototype — always verify messages and links "
    "through official company sources."
)
