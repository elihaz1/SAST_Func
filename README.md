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
# 🔐 Secure Code Review Assistant (OpenAI-based)

This project provides an automated way to analyze code diffs and pull requests using OpenAI's Assistants API, including file exclusion and tool-based analysis (e.g. `code_interpreter`, `file_search`).

---

## 🧪 Features

- Filters sensitive files from diffs (e.g. `.env`, `*.pem`, `credentials`)
- Splits large diffs by file
- Submits chunks to OpenAI Assistant with context
- Waits for threaded responses and consolidates feedback
- Logs debug output if `DEBUG=true`

---

## 🛠️ Assistant Setup

To use this script, you must first create an Assistant via OpenAI's platform:

- Go to: [https://platform.openai.com/assistants](https://platform.openai.com/assistants)
- Create an assistant with the appropriate instructions, tools, and (optionally) uploaded files
- Copy the Assistant ID and use it in your `.env` file

## ⚙️ Environment Variables

Create a `.env` file in the project root with the following keys:

```env
OPENAI_API_KEY=your_openai_api_key
OPENAI_ASSISTANT_ID=your_assistant_id
OPENAI_FILE_IDS=file-id-1,file-id-2  # comma-separated file IDs, optional
DEBUG=true
```

---

## 🚀 Run

as a serveless function 
---

## 🛑 Sensitive File Filtering

The script automatically excludes files containing:

- `.env`, `secret`, `credentials`, `.pem`, `.key`, etc.

Modify `exclude_sensitive_files()` if needed.

---

## 🧩 Dependencies

Install required libraries:

```bash
pip install openai python-dotenv flask
```

---

## 📁 Example `.env`

```env
OPENAI_API_KEY=sk-...
OPENAI_ASSISTANT_ID=asst_...
OPENAI_FILE_IDS=file-abc123,file-def456
DEBUG=true
```