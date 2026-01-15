# TRINETRA — The third eye sees intent, not just input

<p align="center">
  <img src="frontend/assets/trinetra-logo.png" alt="Trinetra Logo" width="220">
</p>

<!-- Add more images/screenshots below as needed -->
<p align="center">
  <!-- Example: <img src="assets/demo.png" width="600"> -->
</p>

## Features

- **Multi-layered LLM Security:**  
  - Prompt injection detection (heuristics + LLM-based)
  - Real-time input scanning and feedback
  - Data validation sandbox for external sources
  - Agentic execution monitoring (code/container safety)
  - Output safety checks (PII, harmful content)

- **Credible Source Finder:**  
  - Finds and validates trusted URLs for factual queries

- **Security Dashboard:**  
  - Scan logs, threat stats, safe/threat URL lists

- **Preprocessing API:**  
  - Text, image (OCR), PDF, document, QR/barcode, and URL extraction

- **Modern UI:**  
  - Cyberpunk dark mode, live diagnostics, interactive feedback

## Approach to Prompt Injection & Data Poisoning

Trinetra uses a layered defense pipeline to secure LLMs:

1. **Instant Detection:**  
   - Fast regex and keyword filters block known prompt injection and jailbreak patterns.
2. **LLM-Based Analysis:**  
   - Groq-powered AI analyzes input for subtle or novel injection attempts, scoring threat levels.
3. **Sandboxed Data Validation:**  
   - External data (URLs, documents) are validated in an isolated agent before reaching the main model.
4. **Agentic Execution Monitoring:**  
   - Tracks logic flow and safely executes generated code in containers to prevent system compromise.
5. **Output Safety Checks:**  
   - Final output is scanned for PII, harmful content, and data poisoning indicators.
6. **Credible Source Enforcement:**  
   - Only trusted, authoritative sources are used for factual queries, reducing risk of misinformation.

This multi-layered approach ensures both proactive and reactive protection against prompt injection and data poisoning.

## Tech Stack

- **Backend:** Python, FastAPI, LangChain, Groq API, SQLite
- **Frontend:** HTML, CSS, JS (no frameworks)
- **Preprocessing:** pdfplumber, pytesseract, pandas, Pillow

## Quick Start

1. **Clone the repo:**
    ```bash
    git clone https://github.com/devikacv001/trinetra.git
    cd trinetra
    ```
2. **Set up environment variables:**  
   Edit the `.env` file in the project root and add your GROQ_API_KEY (GROQ_API_KEY=your_key).
3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4. **Run the backend server:**
    ```bash
    python main.py
    ```
5. **Run the preprocessor API (optional):**
    ```bash
    python preprocessor_app.py
    ```
6. **Open the frontend:**  
   Open `index.html` directly in your browser.

## For Forks & Contributors

- **Backend:**  
  - Set up your `.env` file with the required API key.
  - Start the backend with `python main.py`.
- **Frontend:**  
  - No build step required; just open `index.html`.
  - For local API calls, ensure backend is running on `localhost:8000`.

## API Endpoints

- `/scan` — Full security scan of input
- `/detect` — Real-time prompt injection check
- `/logs` — Get scan logs
- `/metrics` — Get scan statistics
- `/scan/urls` — Get URL classifications

## License

© 2026 TRINETRA™. MIT License.
