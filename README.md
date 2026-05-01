# 🚀 Cognitive Threat Investigator

### AI-Powered Real-Time Cloud Security System

A real-time cloud security platform built with **FastAPI, Machine Learning, and AI-driven analyst reasoning**, featuring a professional enterprise-style dashboard.

---

## 🧠 Overview

Cognitive Threat Investigator is an intelligent security monitoring and response system that:

* Inspects incoming request behavior in real time
* Detects:

  * SQL Injection
  * Cross-Site Scripting (XSS)
  * DDoS-like traffic spikes
  * Behavioral anomalies
* Assigns a dynamic **risk score (0–100)**
* Automatically takes action:

  * **ALLOW**
  * **MONITOR**
  * **RATE_LIMIT**
  * **BLOCK**
* Provides:

  * Live request feed
  * Incident tracking
  * AI-based reasoning
  * Attack story and replay

---

## ❗ Problem Statement

Traditional cloud security systems:

* Focus only on metrics
* Do not explain threats
* Provide limited actionable insights

👉 This creates a gap between **detection and understanding**.

---

## 💡 Solution

This system introduces a **hybrid intelligent security model** that combines:

* Rule-based detection
* Machine learning (Isolation Forest)
* AI-based reasoning

👉 Result: **Explainable, automated, and real-time security decisions**

---

## ⚙️ System Architecture

```text
Client Request
      ↓
FastAPI Backend
      ↓
Detection Layer
  ├─ Rule-Based Engine (SQLi, XSS, DDoS)
  └─ ML Model (Isolation Forest)
      ↓
Risk Scoring Engine
      ↓
AI Analyst Layer
      ↓
Decision Engine (ALLOW / MONITOR / RATE_LIMIT / BLOCK)
      ↓
Dashboard UI
```

---

## 🔍 Detection Engine

### Rule-Based Detection

Detects known attack patterns:

* SQL Injection → `' OR 1=1`
* XSS → `<script>`
* DDoS → high-frequency requests

---

### Anomaly Detection (Machine Learning)

* Model: **Isolation Forest**
* Input features:

  * Request frequency
  * Payload length
  * Endpoint behavior
* Output:

  * Anomaly score

---

## 📊 Risk Scoring

Risk score (0–100) is calculated using:

* Rule triggers
* Anomaly score
* Request frequency

```text
Risk = Rule Score + Anomaly Score + Frequency Weight
```

---

## 🧠 AI Analyst Module

Function:

```python
analyze_with_ai(event_data)
```

### Trigger Conditions:

* `risk_score > 50`
* OR anomaly detected

---

### Input:

* Request details
* Risk score
* Threat type
* Anomaly score

---

### Output:

* Explanation
* Threat Assessment
* Decision Justification
* Recommendation

---

### Fallback:

If AI is unavailable, rule-based reasoning is used to maintain system stability.

---

## ⚙️ Decision Engine

| Risk Score | Action     |
| ---------- | ---------- |
| 0–30       | ALLOW      |
| 31–60      | MONITOR    |
| 61–80      | RATE_LIMIT |
| 81–100     | BLOCK      |

---

## 📡 API Endpoints

| Endpoint          | Method | Description            |
| ----------------- | ------ | ---------------------- |
| `/api/health`     | GET    | Check server status    |
| `/api/events`     | GET    | Retrieve recent events |
| `/api/summary`    | GET    | Get metrics summary    |
| `/api/simulate/*` | POST   | Generate test traffic  |

---

## 🖥️ Dashboard Features

* Sidebar navigation for modular views
* Live request feed with severity highlighting
* Incident panel with risk-based prioritization
* AI Analyst panel with human-like explanations
* Attack Story Mode (step-by-step lifecycle)
* Replay feature for attack simulation

---

## ⚡ Performance Design

* Bounded memory (recent events only)
* Optimized API responses
* UI updates every 2–3 seconds
* No heavy components (graphs/maps removed)

---

## 🔐 Security Considerations

* Input sanitization
* Safe payload handling
* Controlled AI interaction
* Fallback logic for reliability

---

## 🛠️ How to Run the Project

### ✅ Prerequisites

* Python 3.10+ (recommended 3.11)
* pip

---

### 1. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

---

### 2. Start the Server

```bash
python -m uvicorn app:app --reload
```

---

### 3. Open the Application

```
http://127.0.0.1:8000
```

---

### 4. Optional Verification

```bash
python -m py_compile app.py
```

---

## 🏆 Final Outcome

The system delivers:

✔ Real-time threat detection
✔ Explainable AI-based reasoning
✔ Automated response system
✔ Professional cybersecurity dashboard

👉 Transforms traditional monitoring into an **intelligent, explainable security platform**
