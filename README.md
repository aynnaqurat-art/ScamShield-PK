# 🛡️ ScamShield-PK

## AI-Powered Scam Message, Phishing URL & Social Media Link Detection System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Streamlit-Deployed-red?logo=streamlit" alt="Streamlit"/>
  <img src="https://img.shields.io/badge/Scikit--learn-orange?logo=scikitlearn" alt="Scikit-learn"/>
  <img src="https://img.shields.io/badge/VirusTotal-API-green" alt="VirusTotal"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT License"/>
</p>

<p align="center">
  <a href="https://scamshield-pk-k3wbt6sh7tloq93k8bhvbp.streamlit.app/">
    <img src="https://img.shields.io/badge/🚀_Live_Demo-red?style=for-the-badge&logo=streamlit" alt="Live Demo"/>
  </a>
  &nbsp;
  <a href="https://github.com/aynnaqurat-art/ScamShield-PK">
    <img src="https://img.shields.io/badge/💻_Repository-black?style=for-the-badge&logo=github" alt="Repository"/>
  </a>
</p>

---
# 📌 Overview

ScamShield-PK is an AI-powered cybersecurity web application developed to help users identify scam job messages, phishing URLs, and fake social media links before interacting with them.

The application combines Machine Learning, rule-based cybersecurity analysis, URL structural inspection, and external threat intelligence from the VirusTotal API to provide an explainable risk assessment. Instead of relying on a single detection method, ScamShield-PK evaluates multiple security indicators and presents users with a clear risk score, supporting evidence, and actionable recommendations.

Designed as an academic and portfolio project, ScamShield-PK demonstrates the practical application of Artificial Intelligence and Cybersecurity concepts through an interactive web interface deployed on Streamlit Community Cloud.

---
# 🚨 Problem Statement

The rapid growth of digital communication has significantly increased the number of online scams targeting individuals through job advertisements, messaging platforms, emails, and fraudulent websites. Cybercriminals frequently exploit social engineering techniques to manipulate users into revealing sensitive information, making financial payments, or interacting with malicious links.

Many users struggle to distinguish between legitimate and fraudulent content because scam messages often imitate trusted organizations and use persuasive language to create a false sense of urgency. As a result, victims may unknowingly expose personal information or suffer financial losses.

These challenges highlight the need for an accessible solution that can assist users in evaluating potentially suspicious content before taking any action.

---

# 🎯 Project Objectives

ScamShield-PK was developed with the following objectives:

- Detect suspicious job-related messages before users respond to them.
- Identify potentially malicious URLs using multiple security indicators.
- Help users recognize fake or impersonated social media links.
- Provide clear and understandable risk assessments supported by evidence.
- Promote cybersecurity awareness by encouraging safer online decision-making.
- Demonstrate the practical application of Artificial Intelligence and Cybersecurity concepts through an interactive web application.

---
# ✨ Key Features

ScamShield-PK provides a comprehensive set of security-focused features designed to help users identify potential online scams through an intuitive web interface.

### 🤖 AI-Powered Message Analysis
Analyzes suspicious text messages and predicts whether they are legitimate or potentially fraudulent using a machine learning model.

### 🛡️ Hybrid Detection Approach
Combines machine learning predictions with rule-based security checks to improve detection reliability and provide more informative results.

### 🔗 Phishing URL Inspection
Examines URLs for common phishing indicators, including insecure protocols, suspicious domains, URL shorteners, excessive subdomains, and other structural characteristics.

### 🌐 Social Media Link Verification
Identifies trusted social media platforms and helps detect lookalike or impersonated domains that may be used in phishing attacks.

### 🛡️ VirusTotal Reputation Check
Retrieves reputation data from the VirusTotal API, allowing users to view security vendor detections and additional threat intelligence for submitted URLs.

### 📊 Explainable Risk Assessment
Generates an overall risk level together with supporting evidence, enabling users to understand why a message or URL has been classified as suspicious.

### 💡 Security Recommendations
Provides practical recommendations that help users make safer decisions before clicking links, sharing personal information, or responding to suspicious messages.

### ☁️ Interactive Web Application
Offers a responsive and user-friendly interface built with Streamlit, making the system accessible directly through a web browser without requiring installation.

---
# 🏗️ System Architecture

ScamShield-PK follows a modular architecture that processes user inputs through dedicated analysis pipelines before generating a comprehensive security assessment. Each component is designed to perform a specific task, making the application easier to maintain, extend, and improve.

```text
                           ┌────────────────────┐
                           │      User Input     │
                           └─────────┬──────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
            Scam Message                       URL Input
                    │                                 │
                    ▼                                 ▼
        Machine Learning Model              URL Structure Analysis
                    │                                 │
                    ▼                                 ▼
        Rule-Based Security Checks      Social Media Domain Verification
                    │                                 │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
                         VirusTotal Reputation Check
                                    │
                                    ▼
                         Risk Assessment Engine
                                    │
                                    ▼
                    Security Report & Recommendations
```

---

# 🔄 Application Workflow

The overall workflow of ScamShield-PK consists of the following stages:

### Step 1 — User Input
The user submits either a suspicious message or a URL through the web application.

### Step 2 — Content Analysis
The application routes the input to the appropriate analysis module, where relevant security checks are performed.

### Step 3 — Threat Evaluation
Results from different detection components are combined to evaluate the potential security risk.

### Step 4 — Risk Assessment
The application calculates an overall risk level based on the collected evidence and analysis results.

### Step 5 — Security Report
A final report is presented to the user, including the detected risk level, supporting evidence, and practical security recommendations.

---
# 🛠️ Technology Stack

ScamShield-PK was developed using modern technologies for machine learning, cybersecurity analysis, web application development, and cloud deployment. Each technology was selected to provide reliability, scalability, and ease of maintenance.

| Category | Technology | Purpose |
|----------|------------|---------|
| Programming Language | Python 3.11 | Core programming language used to develop the application and implement all detection modules. |
| Web Framework | Streamlit | Provides an interactive web interface for analyzing messages and URLs in real time. |
| Machine Learning | Scikit-learn | Used to build and execute the machine learning model for scam message classification. |
| Natural Language Processing | TF-IDF Vectorizer | Converts textual content into numerical feature vectors suitable for machine learning. |
| Classification Model | Logistic Regression | Predicts whether a message is legitimate or potentially fraudulent. |
| Data Processing | Pandas | Handles and processes structured data during model development and testing. |
| Numerical Computing | NumPy | Supports efficient numerical operations required by the machine learning pipeline. |
| Threat Intelligence | VirusTotal API v3 | Retrieves security reputation information for submitted URLs from multiple security vendors. |
| Version Control | Git & GitHub | Manages source code, version history, and collaborative development. |
| Cloud Deployment | Streamlit Community Cloud | Hosts the application online for public access without requiring local installation. |
| Development Environment | Visual Studio Code | Primary IDE used for application development and debugging. |

---
# 📂 Project Structure

The project is organized into modular components, making the codebase easier to understand, maintain, and extend. Each file is responsible for a specific functionality within the application.

```text
ScamShield-PK/
│
├── app.py
├── url_detector.py
├── virustotal_checker.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── scamshield_pk_ml_model.pkl
├── notebooks/
│
└── screenshots/
```

---

## 📁 Directory Description

| File / Folder | Description |
|---------------|-------------|
| `app.py` | Main Streamlit application that manages the user interface, handles user input, and coordinates the complete detection workflow. |
| `url_detector.py` | Performs structural URL analysis by examining phishing indicators such as suspicious domains, insecure protocols, URL shorteners, and other security-related characteristics. |
| `virustotal_checker.py` | Communicates with the VirusTotal API to retrieve URL reputation information and threat intelligence from multiple security vendors. |
| `scamshield_pk_ml_model.pkl` | Serialized machine learning model used to classify suspicious messages without retraining during application runtime. |
| `requirements.txt` | Lists all Python dependencies required to install and run the project. |
| `README.md` | Contains the complete project documentation, setup instructions, and usage guide. |
| `LICENSE` | Defines the licensing terms under which the project can be used and distributed. |
| `.gitignore` | Specifies files and folders that should not be tracked by Git, such as cache files and virtual environments. |
---

# 🚀 Installation & Setup

Follow the steps below to set up and run ScamShield-PK on your local machine.

## 📋 Prerequisites

Before installing the project, ensure that the following software is available on your system:

- Python 3.11 or later
- Git
- A code editor (Visual Studio Code is recommended)
- A VirusTotal API key (optional, required only for URL reputation analysis)

---

## 📥 Clone the Repository

Clone the project from GitHub using the following command:

```bash
git clone https://github.com/aynnaqurat-art/ScamShield-PK.git
```

Navigate to the project directory:

```bash
cd ScamShield-PK
```

---

## 🐍 Create a Virtual Environment (Recommended)

Creating a virtual environment helps isolate project dependencies from other Python projects.

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 📦 Install Required Dependencies

Install all required Python packages using the following command:

```bash
pip install -r requirements.txt
```

---

## 🔑 Configure the VirusTotal API (Optional)

To enable URL reputation analysis, create a `.streamlit/secrets.toml` file and add your VirusTotal API key:

```toml
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
```

> **Note:** Keep your API key private and never commit it to a public GitHub repository.

---

## ▶️ Run the Application

Start the Streamlit application by executing:

```bash
streamlit run app.py
```

Once the application starts, open the local URL displayed in your terminal (typically `http://localhost:8501`) using your web browser.
---
# 📖 Usage Guide

After launching the application, users can analyze suspicious messages and URLs through an intuitive web interface. Follow the instructions below to use each module.

---

## 💬 Message Analyzer

The **Message Analyzer** helps evaluate suspicious text messages using a hybrid detection approach.

### Steps

1. Open the **Message Analyzer** section.
2. Copy and paste the suspicious message into the input box.
3. Click the **Analyze Message** button.
4. Wait for the analysis to complete.
5. Review the generated security report.

The report includes:

- Classification result
- Confidence level
- Risk score
- Supporting evidence
- Security recommendation

---

## 🔗 URL Analyzer

The **URL Analyzer** evaluates URLs for potential phishing indicators and domain-related security risks.

### Steps

1. Open the **URL Analyzer** section.
2. Enter the complete URL, including `https://` when available.
3. Click the **Analyze URL** button.
4. Review the generated analysis report.

The report may include:

- URL risk level
- Detected security indicators
- Domain verification status
- Structural analysis findings

---

## 🛡️ VirusTotal Reputation Check

If a VirusTotal API key has been configured, the application can retrieve additional threat intelligence for submitted URLs.

### Steps

1. Analyze a URL using the URL Analyzer.
2. Allow the application to request reputation data.
3. Wait for the analysis to complete.
4. Review the reputation summary.

The report displays:

- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected security engines
- Overall reputation assessment

---

## 📊 Understanding the Results

Each analysis produces an easy-to-understand security report.

| Result | Meaning |
|---------|---------|
| **Low Risk** | No significant security indicators were detected. |
| **Medium Risk** | Some suspicious characteristics were identified and should be reviewed carefully. |
| **High Risk** | Multiple indicators suggest that the message or URL may be malicious. Immediate caution is recommended. |

---

## ⚠️ Best Practices

To improve online safety, always follow these recommendations:

- Verify unknown senders before responding.
- Avoid clicking suspicious or shortened links.
- Never share sensitive information without verification.
- Confirm job offers through official company websites.
- Treat urgent requests for money or personal data with caution.
- Use multiple sources to verify suspicious content whenever possible.

---
# 🧠 Machine Learning Pipeline

ScamShield-PK uses a supervised machine learning pipeline to classify suspicious job-related messages. The pipeline transforms raw textual input into numerical representations, enabling the classification model to distinguish between legitimate and potentially fraudulent content.

The workflow consists of multiple stages, each contributing to the final prediction.

---

## 📥 Data Collection

The machine learning model was developed using a labeled dataset containing both legitimate and scam-related messages. The dataset includes examples of common social engineering techniques such as fake job offers, requests for advance payments, credential theft attempts, and urgency-based scams.

---

## 🧹 Text Preprocessing

Before training or prediction, each message undergoes preprocessing to improve data quality and reduce unnecessary variation.

The preprocessing stage includes:

- Converting text to lowercase
- Removing punctuation and special characters
- Eliminating extra whitespace
- Normalizing textual content

These steps produce a cleaner representation of the input while preserving meaningful information.

---

## 🔠 Feature Extraction

After preprocessing, textual data is converted into numerical feature vectors using the **Term Frequency–Inverse Document Frequency (TF-IDF)** technique.

TF-IDF measures the importance of words based on their frequency within individual messages and across the entire dataset. This representation enables the classifier to identify linguistic patterns commonly associated with fraudulent messages.

---

## 🤖 Message Classification

The generated feature vectors are processed by a **Logistic Regression** classifier.

The model estimates the probability that an input message belongs to either of the following categories:

- Legitimate
- Scam

This lightweight algorithm was selected because it provides efficient inference, strong baseline performance, and good interpretability for text classification tasks.

---

## 🛡️ Hybrid Decision Strategy

Machine learning predictions are complemented by additional rule-based security checks. These rules examine message characteristics that may indicate suspicious behavior but are not always captured by statistical learning alone.

The combined evaluation improves the reliability of the final security assessment while providing more transparent results to the user.

---

## 📤 Prediction Output

After completing the analysis, the application generates a structured security report that includes:

- Predicted classification
- Confidence level
- Risk score
- Supporting evidence
- Security recommendation

The final output is presented through the Streamlit interface in a format designed to be understandable for both technical and non-technical users.

---
# 🔗 URL Detection Workflow

In addition to message analysis, ScamShield-PK includes a dedicated URL inspection module designed to identify suspicious or potentially malicious web links. Rather than relying solely on external threat databases, the system performs a structural analysis of each submitted URL to detect characteristics commonly associated with phishing attacks.

This approach enables the application to provide an initial security assessment even when a URL has not yet been reported by public threat intelligence services.

---

## 🔍 URL Analysis Process

Every submitted URL passes through a sequence of security validation checks before a final risk assessment is generated.

```text
User Submits URL
        │
        ▼
URL Format Validation
        │
        ▼
Structural Security Analysis
        │
        ▼
Domain Verification
        │
        ▼
Risk Score Calculation
        │
        ▼
Security Report Generation
```

---

## 🛡️ Security Indicators

The URL analysis module evaluates multiple indicators that are frequently observed in phishing and fraudulent websites.

The inspection includes checks such as:

- Secure HTTPS protocol usage
- Presence of suspicious keywords
- URL shortening services
- IP address–based URLs
- Punycode or encoded domains
- Excessive subdomains
- Abnormally long URLs
- Multiple hyphens within domain names
- Suspicious special characters
- Domain impersonation patterns

Rather than depending on a single indicator, the application evaluates these characteristics collectively to estimate the overall risk associated with the submitted URL.

---

## 📊 Risk Assessment

Each detected security indicator contributes to the overall evaluation process.

Based on the combined analysis, the application classifies the URL into one of the following categories:

| Risk Level | Description |
|------------|-------------|
| **Low Risk** | No significant phishing indicators were detected. |
| **Medium Risk** | Several suspicious characteristics were identified and additional verification is recommended. |
| **High Risk** | Multiple indicators strongly suggest that the URL may be malicious or deceptive. |

---

## 📋 Analysis Output

After completing the inspection, the application generates a structured report containing:

- URL validation status
- Overall risk level
- Detected security indicators
- Domain verification result
- Supporting evidence
- Security recommendation

The generated report is intended to help users understand the reasoning behind the assessment and make informed decisions before visiting potentially unsafe websites.

---
# 🛡️ VirusTotal Integration

To strengthen URL security analysis, ScamShield-PK integrates with the **VirusTotal API v3**, a widely recognized threat intelligence platform that aggregates security assessments from multiple antivirus engines and cybersecurity vendors.

This integration complements the application's internal analysis by providing additional reputation-based insights for submitted URLs.

---

## 🌍 Why VirusTotal?

Structural URL analysis is effective for identifying suspicious patterns, but it cannot always determine whether a URL has already been reported as malicious.

VirusTotal enhances the security assessment by providing publicly available threat intelligence collected from numerous security vendors, enabling users to make more informed decisions before visiting an unknown website.

---

## 🔄 Integration Workflow

The VirusTotal integration follows the workflow below:

```text
User Submits URL
        │
        ▼
ScamShield-PK
        │
        ▼
VirusTotal API
        │
        ▼
Threat Intelligence Retrieval
        │
        ▼
Reputation Analysis
        │
        ▼
Final Security Report
```

---

## 📊 Reputation Information

When a URL reputation report is available, the application presents information such as:

- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected security engines
- Overall reputation status

These results provide additional context that complements the application's internal security assessment.

---

## 🔒 Privacy and Security

ScamShield-PK uses the VirusTotal API solely to retrieve publicly available URL reputation information.

The application does not store user-submitted URLs or maintain any history of reputation lookups. Users should avoid submitting confidential or private URLs to any external threat intelligence service.

---

## 📌 Integration Benefits

The VirusTotal integration provides several advantages:

- Improves confidence in URL reputation assessments.
- Adds external threat intelligence to complement internal analysis.
- Helps identify URLs previously reported by security vendors.
- Enhances transparency by presenting vendor-based reputation results.
- Supports more informed cybersecurity decision-making.

# 🚀 Future Improvements

ScamShield-PK has been designed with a modular architecture that allows future enhancements without significant changes to the existing codebase. The following improvements are planned for future releases:

## 📈 Enhanced Machine Learning Models

Explore transformer-based language models, such as BERT or DistilBERT, to improve classification accuracy and better understand complex linguistic patterns in scam messages.

---

## 🌍 Multilingual Scam Detection

Extend support for additional languages, including Urdu, Roman Urdu, and other regional languages, to improve accessibility for a wider audience.

---

## 📷 Image-Based Scam Detection

Introduce Optical Character Recognition (OCR) to analyze screenshots containing suspicious messages, emails, or advertisements.

---

## 📱 Mobile Application

Develop a cross-platform mobile application that enables users to analyze suspicious content directly from their smartphones.

---

## 🌐 Browser Extension

Create a browser extension capable of evaluating URLs in real time and warning users before they visit potentially unsafe websites.

---

## 🔍 Domain Intelligence Expansion

Enhance URL analysis by incorporating additional domain intelligence sources, including WHOIS information, domain age, SSL certificate validation, and DNS-based security checks.

---

## 📊 Analytics Dashboard

Develop an administrative dashboard that provides insights into detected scam patterns, threat trends, and application usage statistics.

---

## 🔄 Continuous Model Improvement

Regularly update the training dataset with newly identified scam patterns to improve the model's ability to detect emerging threats.

---

## ☁️ Cloud-Based Threat Intelligence

Integrate additional public threat intelligence services to complement existing reputation analysis and improve overall detection coverage.

---

## 🎯 Long-Term Vision

The long-term objective of ScamShield-PK is to evolve into a comprehensive cybersecurity awareness platform that assists users in identifying online scams through intelligent analysis, transparent risk assessment, and continuously updated threat intelligence.

---
# ⚠️ Project Limitations

While ScamShield-PK provides an effective approach for identifying suspicious messages and URLs, it is important to recognize the current scope and limitations of the project.

---

## Limited Detection Scope

The current machine learning model is primarily trained to identify **job-related scam messages**. Although it may recognize other suspicious content, its performance has not been specifically optimized for every category of online scams.

---

## Dependency on Training Data

Like all supervised machine learning systems, the quality of predictions depends on the diversity and quality of the training dataset. Newly emerging scam techniques may require additional training data to maintain detection performance.

---

## Structural URL Analysis

The URL analysis module evaluates structural characteristics commonly associated with phishing attacks. However, a structurally valid URL should not automatically be considered trustworthy.

---

## External Threat Intelligence Availability

VirusTotal reputation results depend on publicly available threat intelligence. Newly created or previously unseen URLs may have limited or no reputation information available.

---

## Internet Connectivity

The VirusTotal reputation service requires an active internet connection. If the external service is unavailable, the application continues to perform its internal analysis but cannot retrieve external reputation data.

---

## Educational and Research Purpose

ScamShield-PK was developed as an academic and portfolio project to demonstrate the practical application of Artificial Intelligence and Cybersecurity techniques. It is not intended to replace commercial security products or enterprise-grade threat detection platforms.

---

## Continuous Improvement

Cybersecurity threats evolve continuously. Maintaining effective detection requires periodic dataset updates, model refinement, and the integration of new threat intelligence sources.
# 🤝 Contributing

Contributions are welcome and appreciated. Whether you would like to report a bug, suggest an enhancement, improve the documentation, or contribute new features, your support is valuable.

If you would like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new feature or bug-fix branch.
3. Implement and test your changes.
4. Commit your modifications with clear commit messages.
5. Submit a Pull Request describing your proposed changes.

Before submitting a contribution, please ensure that:

- The code follows the existing project structure and coding style.
- New functionality is tested before submission.
- Documentation is updated whenever necessary.
- Existing functionality remains unaffected.

Constructive feedback, suggestions, and feature requests are always welcome through GitHub Issues.

---

# 📄 License

This project is licensed under the **MIT License**.

The MIT License permits anyone to use, modify, distribute, and adapt the software for both academic and commercial purposes, provided that the original copyright notice and license are retained.

For complete licensing terms, please refer to the **LICENSE** file included in this repository.

---
# 👩‍💻 Author

**Quratulain**

M.Phil Researcher in Information Technology  
Department of Information Technology  
University of Sargodha, Pakistan

**GitHub Profile:**  
https://github.com/aynnaqurat-art

If you have questions, suggestions, or would like to discuss this project, feel free to connect through GitHub.

---

# ⚠️ Disclaimer

ScamShield-PK is an academic and portfolio project developed to demonstrate the practical application of Artificial Intelligence and Cybersecurity concepts.

The application provides AI-assisted risk assessments based on machine learning, security rules, and publicly available threat intelligence. Although reasonable efforts have been made to improve detection reliability, the results should be considered advisory rather than definitive.

Users should always exercise independent judgment and verify suspicious messages or websites through official and trusted sources before sharing personal information, making financial transactions, or interacting with unknown links.

The author assumes no responsibility for decisions or actions taken based on the results generated by this application.

---

<div align="center">

⭐ If you found this project helpful, please consider starring this repository.

Thank you for visiting ScamShield-PK.

</div>
