import os
import json
import requests
import hmac
import hashlib
import threading
import time
from flask import Request, jsonify, request
from collections import defaultdict

# DEBUGGING
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

def debug_log(message, severity="DEBUG", **kwargs):
    if DEBUG:
        log_entry = {"severity": severity, "message": message}
        log_entry.update(kwargs)
        print(json.dumps(log_entry))

def verify_signature(request: Request, secret: str) -> bool:
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    received_signature = signature.split("=", 1)[1]
    body = request.get_data()
    computed_signature = hmac.new(
        key=secret.encode(),
        msg=body,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed_signature, received_signature)

def exclude_sensitive_files(diff: str) -> str:
    lines = diff.splitlines()
    result = []
    skip = False
    for line in lines:
        if line.startswith('diff --git'):
            filename = line.split(' ')[2].lstrip('b/')
            skip = any(s in filename.lower() for s in [
                '.env', 'secret', 'config', '.pem', '.crt', '.key', 'credentials', 'settings'
            ])
        if not skip:
            result.append(line)
    return '\n'.join(result)

last_processed_lock = threading.Lock()
last_processed = defaultdict(float)
PR_PROCESSING_INTERVAL = 30  # seconds

# Replace with actual secure retrieval from secrets manager
external_api_token = os.environ.get("EXTERNAL_API_TOKEN")
openai_key = os.environ.get("OPENAI_API_KEY")
webhook_token = os.environ.get("WEBHOOK_SECRET")
webhook_shared_token = os.environ.get("WEBHOOK_SIGNATURE_SECRET")
webhook_url = os.environ.get("EXTERNAL_WEBHOOK_URL")

def webhook_entry_point(request: Request):
    try:
        if not verify_signature(request, webhook_shared_token):
            return ":x: Unauthorized: Signature mismatch", 403

        event_type = request.headers.get("X-Event-Key", "")
        data = request.get_json()
        debug_log("Received webhook payload", keys=list(data.keys()) if isinstance(data, dict) else str(type(data)))

        pr = data.get("pullrequest", {})
        pr_id = pr.get("id")
        now = time.time()

        with last_processed_lock:
            if pr_id and now - last_processed[pr_id] < PR_PROCESSING_INTERVAL:
                debug_log("PR recently processed, skipping duplicate", pr_id=pr_id)
                return ":hourglass_flowing_sand: Duplicate webhook", 202
            last_processed[pr_id] = now

        threading.Thread(target=process_webhook, args=(data, event_type)).start()
        return ":white_check_mark: Webhook received", 200

    except Exception as e:
        print(json.dumps({
            "severity": "ERROR",
            "message": "Internal Server Error",
            "error": str(e)
        }))
        return ":x: Internal Server Error", 500

def process_webhook(data, event_type):
    pr = data.get("pullrequest", {})
    pr_id = pr.get("id")
    debug_log("Started process_webhook", pr_id=pr_id)

    try:
        pr_state = pr.get("state", "").upper()
        if pr_state == "MERGED":
            debug_log("PR is already merged, skipping analysis", pr_id=pr_id)
            return

        pr_title = pr.get("title", "[no title]")
        pr_source_branch = pr.get("source", {}).get("branch", {}).get("name", "unknown")
        pr_target_branch = pr.get("destination", {}).get("branch", {}).get("name", "unknown")
        repo = data.get("repository", {})
        workspace = repo.get("workspace", {}).get("slug", "example-workspace")
        repo_slug = repo.get("slug", "example-repo")

        # Replace with actual API endpoint
        diff_url = f"https://api.example.com/repos/{workspace}/{repo_slug}/pullrequests/{pr_id}/diff"
        headers = {"Authorization": f"Bearer {external_api_token}"}
        response = requests.get(diff_url, headers=headers)
        response.raise_for_status()
        raw_diff = response.text
        filtered_diff = exclude_sensitive_files(raw_diff)

        if not filtered_diff.strip():
            debug_log("No relevant diff found after filtering")
            return

        combined_prompt = f"""You are a senior security code reviewer. Analyze the following code diff...
```diff
{filtered_diff}
```"""

        openai_payload = {
            "model": "gpt-4-turbo",
            "messages": [{"role": "user", "content": combined_prompt}],
            "temperature": 0.2
        }
        openai_headers = {
            "Authorization": f"Bearer {openai_key}",
            "Content-Type": "application/json"
        }

        try:
            openai_res = requests.post(
                "https://api.openai.com/v1/chat/completions",
                json=openai_payload,
                headers=openai_headers,
                timeout=30
            )
            content = openai_res.json()["choices"][0]["message"]["content"]
        except requests.exceptions.RequestException as e:
            content = f"[OpenAI ERROR]: {e}"

        summary_text = f"[{event_type}] Security findings for PR #{pr_id}: {pr_title}"
        description_text = f"PR ID: {pr_id}\nTitle: {pr_title}\nSource: {pr_source_branch}\nTarget: {pr_target_branch}\n\n```markdown\n{content.strip()}\n```"

        webhook_payload = {
            "issues": ["SECURITY-REVIEW"],
            "data": {
                "Summary": summary_text,
                "Description": description_text
            }
        }

        webhook_headers = {
            "Content-Type": "application/json",
            "X-Automation-Webhook-Token": webhook_token
        }

        requests.post(webhook_url, headers=webhook_headers, json=webhook_payload, verify=True)

    except Exception as e:
        print(json.dumps({
            "severity": "ERROR",
            "message": "Internal Server Error",
            "error": str(e)
        }))
