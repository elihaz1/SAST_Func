import os
import json
import requests
import hmac
import hashlib
import threading
import time
import openai
from flask import Request, jsonify, request
from collections import defaultdict

# DEBUG mode from environment variable
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

def split_diff_by_file(diff: str, max_size: int = 256000) -> list:
    chunks = []
    current_chunk = []
    current_size = 0

    for line in diff.splitlines():
        if line.startswith('diff --git') and current_chunk:
            if current_size >= max_size:
                chunks.append('\n'.join(current_chunk))
                current_chunk = []
                current_size = 0

        current_chunk.append(line)
        current_size += len(line) + 1  # +1 for newline

    if current_chunk:
        chunks.append('\n'.join(current_chunk))

    return chunks

def call_openai_for_security_analysis(diff: str, openai_key: str) -> str:
    openai.api_key = openai_key
    assistant_id = os.environ.get("OPENAI_ASSISTANT_ID")

    try:
        debug_log("[OpenAI] Creating new thread")
        thread = openai.beta.threads.create()
        thread_id = thread.id
        debug_log("[OpenAI] Thread created", thread_id=thread_id)

        chunks = split_diff_by_file(diff)
        for i, chunk in enumerate(chunks):
            openai.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=chunk
            )
            debug_log("[OpenAI] Message chunk posted", chunk_index=i, chunk_size=len(chunk))

        run = openai.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id
        )
        debug_log("[OpenAI] Assistant run started", run_id=run.id)

        debug_log("[OpenAI] Waiting for run to complete")
        while run.status not in ["completed", "failed"]:
            time.sleep(1.5)
            run = openai.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run.id)
            debug_log("[OpenAI] Polling run status", status=run.status)

        if run.status == "completed":
            messages = openai.beta.threads.messages.list(thread_id=thread_id)
            sorted_messages = sorted(messages.data, key=lambda m: m.created_at, reverse=True)
            result_message = sorted_messages[0].content[0].text.value
            debug_log("[OpenAI] Extracted message from assistant", message_preview=result_message[:300])
            return result_message
        else:
            debug_log("[OpenAI] Assistant run failed", status=run.status)
            return f"Assistant run failed with status: {run.status}"
    except Exception as e:
        debug_log(f"OpenAI Assistant request failed: {str(e)}", severity="ERROR")
        return f"Error during assistant analysis: {str(e)}"

# Global PR state tracking
last_processed_lock = threading.Lock()
last_processed = defaultdict(float)
PR_PROCESSING_INTERVAL = 30  # seconds

# Environment secrets
wsat = os.environ.get("GIT_SERVICE_TOKEN")
openai_key = os.environ.get("OPENAI_API_KEY")
webhook_token = os.environ.get("TICKET_SERVICE_WEBHOOK_TOKEN")
webhook_shared_token = os.environ.get("WEBHOOK_SHARED_SECRET")
webhook_url = os.environ.get("TICKET_SERVICE_WEBHOOK_URL")

def webhook_entry_point(request: Request):
    try:
        if not verify_signature(request, webhook_shared_token):
            return ":x: Unauthorized: Signature mismatch", 403

        event_type = request.headers.get("X-Event-Key", "")
        if event_type == "pullrequest:fulfilled":
            debug_log("Received merged PR event - updating existing ticket", event_type=event_type, severity="INFO"), 200

        data = request.get_json()
        debug_log("Received webhook payload", keys=list(data.keys()) if isinstance(data, dict) else str(type(data)))

        pr = data.get("pullrequest", {})
        pr_id = pr.get("id")
        now = time.time()

        with last_processed_lock:
            if pr_id and now - last_processed[pr_id] < PR_PROCESSING_INTERVAL:
                debug_log("PR recently processed, skipping duplicate (entry point)", pr_id=pr_id, severity="INFO")
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
    debug_log("Started process_webhook", thread_id=threading.get_ident(), timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'), pr_id=pr_id)

    try:
        start_time = time.time()
        pr_author = pr.get("author", {}).get("display_name", "unknown")
        pr_title = pr.get("title", "[no title]")
        pr_source_branch = pr.get("source", {}).get("branch", {}).get("name", "unknown")
        pr_target_branch = pr.get("destination", {}).get("branch", {}).get("name", "unknown")
        repo = data.get("repository", {})
        repo_name = repo.get("name", "unknown")
        workspace_info = repo.get("workspace") or data.get("workspace") or {}
        workspace = workspace_info.get("slug")
        repo_slug = repo.get("slug") or repo.get("full_name", "").split("/")[-1]

        if not workspace or not repo_slug:
            debug_log("Missing workspace or repo_slug in payload", workspace=workspace, repo_slug=repo_slug)
            return

        diff_url = f"https://api.git-service.org/2.0/repositories/{workspace}/{repo_slug}/pullrequests/{pr_id}/diff"
        headers = {"Authorization": f"Bearer {wsat}"}
        debug_log("Fetching PR diff", diff_url=diff_url)
        response = requests.get(diff_url, headers=headers)
        response.raise_for_status()

        raw_diff = response.text
        debug_log("PR diff fetched", size=len(raw_diff))

        filtered_diff = exclude_sensitive_files(raw_diff)
        debug_log("Filtered sensitive files from diff", filtered_size=len(filtered_diff))

        valid_targets = ["main", "master", "release"]
        if pr_target_branch.lower() not in valid_targets:
            debug_log(
                "Target branch is not a main/release branch — skipping analysis",
                pr_id=pr_id,
                target_branch=pr_target_branch
            )
            return
        if not filtered_diff.strip():
            debug_log("No diff to analyze after sensitive file filtering", severity="WARNING")
            return

        content = call_openai_for_security_analysis(filtered_diff, openai_key)
        debug_log("OpenAI analysis received", preview=content[:200], pr_id=pr_id)

        analysis_id = f"{pr_id}-{pr_source_branch}"
        summary_text = f"[Security Review] PR #{pr_id}: {pr_title}"

        description_text = f"""
*Repository:* {repo_name}  
*PR ID:* {pr_id}  
*Title:* {pr_title}  
*Author:* {pr_author}  
*Source Branch:* {pr_source_branch}  
*Target Branch:* {pr_target_branch}  

### Analysis ID:
{analysis_id}

### Findings:
{content.strip()}
"""

        webhook_payload = {
            "issues": ["SEC-123"],
            "data": {
                "Summary": summary_text,
                "Description": description_text
            }
        }
        webhook_headers = {
            "Content-Type": "application/json",
            "X-Automation-Webhook-Token": webhook_token
        }

        debug_log("Sending webhook to external system", url=webhook_url)
        webhook_response = requests.post(
            webhook_url,
            headers=webhook_headers,
            json=webhook_payload,
            verify=True,
        )

        if webhook_response.status_code >= 400:
            debug_log("Webhook failed", status_code=webhook_response.status_code, response_text=webhook_response.text[:300], severity="ERROR")
        else:
            debug_log("Webhook sent successfully", status_code=webhook_response.status_code)

        total_duration = time.time() - start_time
        debug_log("Webhook processing completed", duration=f"{total_duration:.2f}s")

    except Exception as e:
        print(json.dumps({
            "severity": "ERROR",
            "message": "Unhandled exception in process_webhook",
            "error": str(e)
        }))
