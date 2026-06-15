# Data Access Audit & Insider Threat Detection 🛡️

## Overview

The **Data Access Audit & Insider Threat Detection** system is an advanced security solution designed to identify and flag suspicious data access patterns within an organization. By utilizing a hybrid approach that combines **Behavioral Machine Learning (Isolation Forest)** with a **Rule-Based Alerting Engine**, the system effectively detects both novel anomalies and deterministic policy violations. The final risk assessments are enriched by an **LLM-powered narrative engine** that generates clear, explainable, and actionable incident reports.

## Problem Statement

### 1. Background & Motivation

Insider threats—whether malicious or accidental—pose a severe risk to organizational data security. Traditional systems face several challenges:

- **Static Rule Limitations:** Pure rule-based systems generate high false positives and fail to catch novel, "out-of-policy" anomalies.
- **Lack of Explainability:** Pure ML models act as "black boxes," making it difficult for security analysts to understand _why_ an alert was triggered.
- **Context Blindness:** Alerts often lack user context (role, typical working hours, data sensitivity), slowing down incident response.

### 2. Solution Approach

To overcome these challenges, our system integrates ML and rule-based logic in a unified pipeline:

- **Feature Engineering:** Extracts key behavioral data points (Time of access, Data sensitivity, Volume, Destination, Frequency).
- **Dual-Engine Processing:** \* _Machine Learning:_ An Isolation Forest model identifies unsupervised behavioral anomalies.
  - _Rules Engine:_ Evaluates deterministic policies defined via JSON configurations.
- **Hybrid Risk Scoring:** Combines the ML anomaly score and Rule risk score into a unified threat metric.
- **LLM Narratives:** Translates the combined scores and context into human-readable incident reports (e.g., "Finance analyst accessed 50k customer records at 3 AM to personal email = HIGH RISK").

## System Architecture

Our architecture is designed for parallel processing and comprehensive risk evaluation:

**1. UI & User Interaction**
📌 The user (Security Analyst) interacts with a web interface to click the upload button and submit audit logs (CSV files).

**2. Data Preprocessing & Ingestion Layer**
✅ Cleans and standardizes the incoming CSV audit log data.
✅ Prepares the structured data for feature extraction.

**3. Feature Engineering**
📍 Extracts core behavioral features per user per day.
📍 Analyzes time of access, volume, data sensitivity, destination, and frequency.

**4. Parallel Evaluation Engines**

- **Model (Isolation Forest):** Works on unsupervised data to calculate an _Anomaly Score_ and _Risk Score_ based on deviations from baseline behavior.
- **Rules Engine:** Evaluates access against predefined custom rules (e.g., tracking exceptions like bulk exports on Fridays) to generate a _Rule Risk Score_ and _Rules Context_.

## Rule-Based Insider Threat Detection Logic

The system applies a set of predefined rules to identify potentially suspicious insider activities. Each triggered rule contributes a risk score, which is aggregated to determine the overall threat level.

| Rule ID  | Rule Name                                      | Detection Condition                                                                                             | Risk Score |
| -------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------- |
| **R001** | High Sensitivity Access Outside Business Hours | `resource_sensitivity == 'high' AND time_classification != 'business_hours'`                                    | 30         |
| **R002** | Sensitive Data Export                          | `resource_sensitivity == 'high' AND action == 'export_data'`                                                    | 40         |
| **R003** | Dormant Account Activity                       | `days_inactive > 30`                                                                                            | 50         |
| **R004** | Inactive Employee Activity                     | `is_active == False`                                                                                            | 150        |
| **R005** | Privilege Misuse                               | `privilege_level == 'user' AND resource_sensitivity == 'high' AND action IN ('admin_operation', 'export_data')` | 50         |
| **R006** | Weekend Access                                 | `time_classification == 'weekend'`                                                                              | 20         |
| **R007** | Department–Resource Mismatch                   | `department == 'Marketing' AND resource == 'HRIS'`                                                              | 35         |

### Risk Scoring

Multiple rules may be triggered for a single event. The total risk score is calculated as:

```text
Total Risk Score = Σ (Risk Score of Triggered Rules)
```

### Threat Classification

| Total Risk Score | Threat Level |
| ---------------- | ------------ |
| 0 – 29           | Low          |
| 30 – 59          | Medium       |
| 60 – 99          | High         |
| ≥ 100            | Critical     |

**5. Combined Risk Evaluation**
🎛 Merges the separate outputs from the ML Model and Rules Engine into a unified **Combined Risk Score + Context**.

**6. LLM Incident Report**
🎬 Feeds the combined risk data into a Large Language Model.
✅ Outputs a highly readable, context-rich incident report and risk dashboard summary for the security team.

## Key Features

- **✔️ Hybrid Threat Detection** – Combines the adaptability of ML with the precision of static rules.
- **✔️ Behavioral Feature Engineering** – Analyzes deep contextual metrics (volume, time, sensitivity, destination).
- **✔️ Automated LLM Narratives** – Explains _why_ a threat was flagged in plain English with recommended actions.
- **✔️ Unsupervised ML Model** – Uses Isolation Forest to detect previously unseen attack vectors without labeled data.
- **✔️ Customizable JSON Rules** – Allows easy implementation of company-specific security policies and exceptions.
- **✔️ Visual Risk Dashboard** – Provides a simple UI for uploading data and viewing flagged access events.

## Tech Stack

- **Machine Learning:** Python, Scikit-learn (Isolation Forest), PyTorch, Pandas
- **Rule Engine:** Custom JSON-based rule processor
- **LLM Integration:** OpenAI API / HuggingFace Transformers
- **Backend:** Python REST API (Flask / FastAPI)
- **Database:** PostgreSQL (for tracking alerts and rules)
- **Frontend:** React / Vite, Plotly (for risk dashboards)

## Contribution Guidelines

1. Fork the repository
2. Create a new feature branch (`feature-xyz`)
3. Commit your changes (`git commit -m 'Added feature XYZ'`)
4. Push to the branch (`git push origin feature-xyz`)
5. Create a pull request for review

## License

This project is licensed under the MIT License.

## Contact

For queries and contributions, reach out via [email/contact link].
🚀 Securing Data Access with Hybrid AI and Intelligent Alerting! 🛡️
