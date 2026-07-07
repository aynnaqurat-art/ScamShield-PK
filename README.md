# ScamShield-PK

A hybrid SMS and job scam detection system built with Machine Learning and rule-based risk analysis.

## Features

- Detects scam, suspicious, and legitimate SMS/job messages
- Uses a TF-IDF + Logistic Regression machine learning model
- Adds rule-based evidence detection for high-risk signals
- Detects CNIC requests, OTP requests, verification fees, urgency, WhatsApp-only contact, and unrealistic salary claims
- Provides a risk score, risk level, detected evidence, and safety recommendation
- Includes a Streamlit web application interface

## Dataset

The ML model was trained using the SMS Spam Collection dataset from Kaggle.

- Total messages: 5,572
- Legitimate messages: 4,825
- Scam/spam messages: 747
- Train-test split: 80% training and 20% testing
- Model test accuracy: approximately 98%

Dataset source: https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset

## Technologies Used

- Python
- Pandas
- Scikit-learn
- TF-IDF Vectorizer
- Logistic Regression
- Streamlit
- Joblib

## How It Works

1. The user enters an SMS or job-related message.
2. The ML model calculates scam probability.
3. The rule-based engine checks for risky indicators.
4. Both results are combined into a final prediction:
   - Legitimate
   - Suspicious
   - Scam
5. The system shows a risk score and a recommended safety action.

## Run Locally

Install required packages:

```bash
pip install streamlit pandas scikit-learn joblib
