# Security Analysis Webhook Function

This project provides a **serverless function** that handles pull request webhooks, scans diffs for security issues using a language model (LLM), and posts the results to an external issue tracking system (e.g., Jira). 


It is designed to run in **Function-as-a-Service (FaaS)** environments such as:
- Google Cloud Functions
- AWS Lambda (via Flask + adapter like Zappa)
- Azure Functions (via WSGI wrapper)
- Any other serverless platform that accepts HTTP requests

---

## 🔍 Features

- Signature verification to ensure webhook authenticity
- Filtering out sensitive files (e.g., `.env`, `secrets`, `*.pem`, etc.)
- Sends the diff to OpenAI's API for security analysis
- Returns summarized findings in Markdown
- Supports rate limiting for duplicate events
- Posts results to a specified webhook (e.g., Jira)

---

## 🚀 Getting Started

### Prerequisites

- Python 3.7+
- Flask (if running locally or on a platform that uses WSGI)
- Function-compatible entry point (see below)
- Make sure to create a Pull Request webhook for all active repositories.


### Installation (Local Testing)

```bash
pip install -r requirements.txt
```

---

## ⚙️ Environment Variables

Set the following variables in your deployment environment:

| Variable Name             | Description                                
|---------------------------|-------------------------------------------------------------
| `DEBUG`                   | Enable verbose logging (true/false)        
| `EXTERNAL_API_TOKEN`      | Token to fetch PR from GIT diffs                    
| `OPENAI_API_KEY`          | OpenAI API key                             
| `WEBHOOK_SECRET`          | Token to authenticate outgoing webhook to ticketing system   
| `WEBHOOK_SIGNATURE_SECRET`| Secret for validating incoming signatures 
| `EXTERNAL_WEBHOOK_URL`    | Where to send the final analysis summary to ticketing system

---

## 🧪 Local Testing

You can run this as a basic Flask app for testing:

```python
from flask import Flask, request
from sastFunc import webhook_entry_point

app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    return webhook_entry_point(request)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

> For Google Cloud Functions, simply export `webhook_entry_point()` as the function handler.

---

## 🧱 Function Entry Point

To deploy as a serverless function:

- **Google Cloud Functions**:  
  Use `webhook_entry_point` as your entry point (target)
  
- **AWS Lambda (via Flask + Zappa)**:  
  Deploy `app` object with handler mapped to `/webhook`

- **Azure Functions**:  
  Use a WSGI adapter to wrap Flask

---

## 📑 Example Output

The Markdown summary includes:
- Finding title
- File and line number
- Explanation of the issue
- Relevant code snippet (up to 3 lines)

---

## ✅ Development Notes

- Diffs are filtered using the `exclude_sensitive_files()` function.
- Analysis is performed using OpenAI's GPT-4 Turbo with a low temperature for consistent results.
- All secrets are injected via environment variables (never hardcoded).

---

## 🛡️ Disclaimer

This code is intended for educational and internal tooling purposes. Review and test carefully before deploying to production environments.

---

## 📬 Contributions

Feel free to open issues or submit PRs to:
- Expand Git provider integrations
- Add analysis enrichment
- Improve resiliency and logging