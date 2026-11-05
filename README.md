# Phishing Detection & Analysis System

SOC Blue Team Email Analysis and Incident Triage Platform

## 1. Project Overview

This graduation project implements an email phishing detection system integrated with Wazuh SIEM.

The system analyzes uploaded EML files using rule-based detection, a Machine Learning model, and URLhaus threat intelligence.

Suspicious findings can generate security alerts for SOC monitoring.

## 2. Main Features

- Email header, body, URL, and attachment analysis
- SPF, DKIM, and DMARC result inspection
- Rule-based phishing risk scoring
- TF-IDF and Logistic Regression classification
- URLhaus threat intelligence integration
- SOC web dashboard built with FastAPI
- HTTP Basic Authentication
- Automated PDF incident reports
- JSON security alerts integrated with Wazuh
- MITRE ATT&CK T1566 mapping

## 3. Technology Stack

- Python
- FastAPI and Uvicorn
- Scikit-learn
- BeautifulSoup
- ReportLab
- HTML, CSS, and JavaScript
- Wazuh SIEM
- Docker

## 4. Project Structure

- app/ - Application source code
- models/ - Trained Machine Learning model
- samples/ - Email samples for testing
- data/ - Local training datasets
- logs/ - Generated SOC security alerts
- reports/ - Generated PDF incident reports

## 5. Installation

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install project dependencies:

```bash
python -m pip install -r requirements.txt
```

## 6. Environment Configuration

Create a `.env` file in the project root.

Required SOC authentication settings:

```text
SOC_DASHBOARD_USERNAME=socadmin
SOC_DASHBOARD_PASSWORD=replace_with_a_strong_password
```

Optional URLhaus integration:

```text
URLHAUS_AUTH_KEY=your_urlhaus_api_key
```

Do not commit `.env` to Git.

## 7. Running the Application

From the project root:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

http://127.0.0.1:8000/dashboard

Sign in with the configured SOC account.

## 8. Email Analysis Workflow

1. Upload an EML file.
2. Validate the uploaded email.
3. Extract email information and URLs.
4. Run rule-based detection.
5. Run Machine Learning classification.
6. Check available threat intelligence.
7. Produce the final assessment.
8. Generate a PDF incident report.
9. Write a SIEM alert when the assessment requires investigation.

## 9. Wazuh SIEM Integration

The application writes JSON security events to:

```text
logs/phishing_alerts.json
```

The Wazuh agent monitors this file using a JSON localfile configuration.

The Wazuh manager uses custom rule ID 100110 with alert level 12 to identify phishing detection events.

MITRE ATT&CK technique: T1566 - Phishing.

The Wazuh integration requires separate agent and manager configuration.

## 10. Machine Learning Evaluation

The model uses TF-IDF features with Logistic Regression.

Evaluation results on the held-out test dataset:

- Accuracy: 98.32%
- Precision: 97.28%
- Recall: 98.24%
- F1-score: 97.76%
- False positive rate: 1.64%

These results describe the evaluated dataset and do not guarantee equivalent performance on unseen email sources.

## 11. Security Controls

- HTTP Basic Authentication for analysis and report endpoints
- EML file extension validation
- Maximum upload size of 5 MB
- Empty-file rejection
- Email sender header validation
- Report filename validation
- Exclusion of credentials, incident logs, and reports from Git

Use HTTPS before exposing HTTP Basic Authentication beyond the local development environment.

## 12. Project Status

Working prototype with tested email analysis, PDF reporting, SOC authentication, and Wazuh alert integration.

## 13. Wazuh Integration Configuration

The Wazuh configuration templates are available in:

- `integration/wazuh/agent-localfile.xml`
- `integration/wazuh/phishing_detection_rules.xml`

### Wazuh Agent Setup

1. Install and register a Wazuh agent on the Ubuntu analysis machine.
2. Open `/var/ossec/etc/ossec.conf`.
3. Add the `<localfile>` block from `agent-localfile.xml` inside the existing `<ossec_config>` configuration.
4. Replace the example location with the absolute path to `logs/phishing_alerts.json`.
5. Validate the configuration and restart the Wazuh agent.

### Wazuh Manager Setup

1. Place `phishing_detection_rules.xml` in the manager's `/var/ossec/etc/rules/` directory.
2. Verify that parent rule `86600` is available in the deployed Wazuh version.
3. Validate the detection rule using `wazuh-logtest`.
4. Restart the Wazuh manager after validating the configuration.
5. Upload a synthetic phishing email through the SOC Dashboard.
6. Verify that rule `100110` generates a level 12 alert in Wazuh Threat Hunting.

### Integration Details

- Event format: JSON
- Event type: `phishing_detection`
- Custom detection rule: `100110`
- Severity level: `12`
- MITRE ATT&CK technique: `T1566`
- Monitoring source: `logs/phishing_alerts.json`

The application and Wazuh Manager can run on separate machines.
