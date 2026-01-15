# 🔐 TRINETRA  
### *The third eye sees intent, not just input*

<p align="center">
  <img src="frontend/assets/trinetra-logo.png" alt="Trinetra Logo" width="220">
</p>

---

## 🖥️ Screenshots

<p align="center">
  <img src="screenshots/screen1.png" width="100%">
  <img src="screenshots/screen2.png" width="100%">
  <img src="screenshots/screen3.png" width="100%">
</p>

<p align="center">
  <img src="screenshots/screen4.png" width="100%">
    The above screen shows the front page of Trinetra  

  <img src="screenshots/screen5.png" width="100%">
  <img src="screenshots/screen6.png" width="100%">
</p>

<p align="center">
  <img src="screenshots/screen7.png" width="100%">
  <img src="screenshots/screen8.png" width="100%">
  <img src="screenshots/screen9.png" width="100%">
</p>

---

## 🚀 Overview

**TRINETRA** is an AI-native security system designed to protect Large Language Model (LLM) applications from **prompt injection**, **jailbreaks**, and **data poisoning attacks**.

Unlike traditional filters, Trinetra focuses on **intent analysis**, not just keyword matching—providing proactive, layered defense across input, execution, and output stages.

---

## ✨ Features

### 🛡️ Multi-Layered LLM Security
- Prompt injection detection (heuristics + LLM-based)
- Real-time input scanning and feedback
- Data validation sandbox for external sources
- Agentic execution monitoring (safe code/container execution)
- Output safety checks (PII, harmful or poisoned content)

### 🔗 Credible Source Finder
- Identifies and enforces trusted, authoritative URLs
- Reduces hallucinations and misinformation

### 📊 Security Dashboard
- Scan logs and threat statistics
- Safe vs malicious input tracking
- URL classification insights

### 🔍 Preprocessing API
- Text normalization
- Image OCR
- PDF & document parsing
- QR / barcode scanning
- URL extraction and validation

### 🎨 Modern UI
- Cyberpunk-inspired dark mode
- Live diagnostics
- Interactive threat feedback

---

## 🧠 Approach to Prompt Injection & Data Poisoning

Trinetra uses a **defense-in-depth pipeline**:

1. **Instant Detection**  
   Regex and pattern-based filters block known jailbreak and injection attempts.

2. **LLM-Based Analysis**  
   Groq-powered analysis detects subtle, novel, or obfuscated attacks and assigns threat scores.

3. **Sandboxed Data Validation**  
   External data (URLs, documents) is processed in isolated agents before reaching the main model.

4. **Agentic Execution Monitoring**  
   Generated logic and code are tracked and safely executed to prevent system compromise.

5. **Output Safety Checks**  
   Final responses are scanned for PII leaks, harmful content, and poisoned data.

6. **Credible Source Enforcement**  
   Factual queries are answered only using trusted sources.

This ensures both **proactive prevention** and **reactive containment**.

---

## 🧰 Tech Stack

- **Backend:** Python, FastAPI, LangChain, Groq API, SQLite  
- **Frontend:** HTML, CSS, JavaScript (no frameworks)  
- **Preprocessing:** pdfplumber, pytesseract, pandas, Pillow  

---

## ⚡ Quick Start

### 1️⃣ Clone the repository
```bash
git clone https://github.com/devikacv001/trinetra.git
cd trinetra
