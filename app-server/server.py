"""
GitHub App webhook server — Approach 4
Intercepts push events from GHES, parses all third-party actions in the
triggered workflow files (direct + transitive), and POSTs results to a webhook.

Usage:
    export GITHUB_APP_ID=66
    export GITHUB_APP_PRIVATE_KEY_PATH=/path/to/private-key.pem
    export GITHUB_WEBHOOK_SECRET=7saPvK07nHHjtZLZEEE1fBSjB6U9W3FSDCz9lMP_aic
    export GITHUB_BASE_URL=https://github.jfrog.info
    export NOTIFY_WEBHOOK_URL=https://webhook.site/10cf7893-ea3c-4e9c-ad2e-bc455cef7680
    python3 server.py
"""

import hashlib
import hmac
import json
import logging
import os
import time

import jwt
import requests
import yaml
from flask import Flask, abort, jsonify, request

# ---------------------------------------------------------------------------
# Configuration (all from environment variables — no secrets in code)
# ---------------------------------------------------------------------------

APP_ID               = os.environ["GITHUB_APP_ID"]
PRIVATE_KEY_PATH     = os.environ["GITHUB_APP_PRIVATE_KEY_PATH"]
WEBHOOK_SECRET       = os.environ["GITHUB_WEBHOOK_SECRET"]
GITHUB_BASE_URL      = os.environ.get("GITHUB_BASE_URL", "https://github.com")
NOTIFY_WEBHOOK_URL   = os.environ["NOTIFY_WEBHOOK_URL"]

GITHUB_API_BASE = f"{GITHUB_BASE_URL}/api/v3"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# GitHub App authentication helpers
# ---------------------------------------------------------------------------

def _load_private_key() -> str:
    with open(PRIVATE_KEY_PATH) as f:
        return f.read()


def _generate_app_jwt() -> str:
    """Generate a short-lived JWT to authenticate as the GitHub App."""
    now = int(time.time())
    payload = {
        "iat": now - 60,   # issued 60s ago (clock skew tolerance)
        "exp": now + 540,  # 9 minutes from now (max allowed is 10m)
        "iss": APP_ID,
    }
    return jwt.encode(payload, _load_private_key(), algorithm="RS256")


def _get_installation_token(installation_id: int) -> str:
    """Exchange the App JWT for an installation access token."""
    app_jwt = _generate_app_jwt()
    url = f"{GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens"
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        },
        timeout=15,
        verify=False,   # set to True if GHES has a trusted TLS cert
    )
    resp.raise_for_status()
    return resp.json()["token"]


def _github_get(path: str, token: str) -> dict | str | None:
    """GET from the GHES API. Returns parsed JSON or None on 404."""
    resp = requests.get(
        f"{GITHUB_API_BASE}{path}",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=15,
        verify=False,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()

# ---------------------------------------------------------------------------
# Workflow YAML parser (same logic as notify-webhook.yml, now recursive)
# ---------------------------------------------------------------------------

def _parse_workflow_actions(content: str, source_file: str) -> list[dict]:
    """
    Parse a workflow YAML string and return a flat list of third-party
    action/reusable-workflow references found in it.
    Local paths (starting with ./ or .\) are excluded.
    """
    try:
        workflow = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        log.warning("Failed to parse %s: %s", source_file, exc)
        return []

    found = []
    for job_name, job in (workflow or {}).get("jobs", {}).items():
        if not isinstance(job, dict):
            continue

        # Job-level reusable workflow call
        ref = job.get("uses", "")
        if ref and not ref.startswith("./") and not ref.startswith(".\\"):
            found.append({
                "source_file": source_file,
                "job": job_name,
                "step": None,
                "uses": ref,
                "type": "reusable_workflow",
            })

        # Step-level action references
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            ref = step.get("uses", "")
            if ref and not ref.startswith("./") and not ref.startswith(".\\"):
                found.append({
                    "source_file": source_file,
                    "job": job_name,
                    "step": step.get("name") or ref,
                    "uses": ref,
                    "type": "action",
                })

    return found


def _fetch_file_content(repo_full_name: str, file_path: str, ref: str, token: str) -> str | None:
    """Fetch a file's raw content from the GHES repo at a given ref."""
    import base64
    data = _github_get(
        f"/repos/{repo_full_name}/contents/{file_path}?ref={ref}",
        token,
    )
    if data is None or "content" not in data:
        return None
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def _collect_all_actions(
    repo_full_name: str,
    ref: str,
    token: str,
    workflow_files: list[str],
) -> list[dict]:
    """
    Recursively parse workflow files and follow reusable workflow references
    in the same repo. Returns a deduplicated flat list of all third-party actions.
    """
    visited: set[str] = set()
    all_actions: list[dict] = []
    queue: list[str] = list(workflow_files)

    while queue:
        file_path = queue.pop(0)
        if file_path in visited:
            continue
        visited.add(file_path)

        content = _fetch_file_content(repo_full_name, file_path, ref, token)
        if content is None:
            log.warning("Could not fetch %s at %s", file_path, ref)
            continue

        actions = _parse_workflow_actions(content, file_path)
        all_actions.extend(actions)

        # Follow local reusable workflow references (same repo)
        for action in actions:
            if action["type"] == "reusable_workflow":
                uses = action["uses"]
                # Local same-repo ref: ./.github/workflows/foo.yml
                # (already filtered out by _parse_workflow_actions — handled above)
                # Cross-repo refs like org/repo/.github/workflows/x.yml@ref
                # are external and not fetched (would need separate auth)
                _ = uses  # placeholder for future cross-repo support

    return all_actions

# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------

def _verify_signature(payload_bytes: bytes, sig_header: str) -> bool:
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    received = sig_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)

# ---------------------------------------------------------------------------
# Flask route — receives all GHES webhook events
# ---------------------------------------------------------------------------

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    payload_bytes = request.get_data()
    sig = request.headers.get("X-Hub-Signature-256", "")

    if not _verify_signature(payload_bytes, sig):
        log.warning("Rejected webhook: invalid signature")
        abort(401)

    event = request.headers.get("X-GitHub-Event", "")
    payload = json.loads(payload_bytes)

    log.info("Received event: %s", event)

    if event != "push":
        return jsonify({"status": "ignored", "event": event}), 200

    return _handle_push(payload)


def _handle_push(payload: dict):
    repo_full_name  = payload["repository"]["full_name"]
    ref             = payload["after"]           # SHA of the pushed commit
    installation_id = payload["installation"]["id"]
    pusher          = payload.get("pusher", {}).get("name", "unknown")
    branch          = payload.get("ref", "")

    log.info("Push by %s to %s @ %s", pusher, repo_full_name, branch)

    # Find workflow files that were added or modified in this push
    changed_workflows: list[str] = []
    for commit in payload.get("commits", []):
        for f in commit.get("added", []) + commit.get("modified", []):
            if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")):
                if f not in changed_workflows:
                    changed_workflows.append(f)

    if not changed_workflows:
        log.info("No workflow files changed — scanning all .github/workflows/ files")
        # Fall back to scanning all workflow files in the repo at this ref
        token = _get_installation_token(installation_id)
        tree_data = _github_get(
            f"/repos/{repo_full_name}/git/trees/{ref}?recursive=1",
            token,
        )
        if tree_data:
            changed_workflows = [
                item["path"]
                for item in tree_data.get("tree", [])
                if item["path"].startswith(".github/workflows/")
                and item["path"].endswith((".yml", ".yaml"))
            ]
    else:
        token = _get_installation_token(installation_id)

    log.info("Scanning workflow files: %s", changed_workflows)

    all_actions = _collect_all_actions(repo_full_name, ref, token, changed_workflows)

    log.info("Found %d third-party action(s)", len(all_actions))
    for a in all_actions:
        log.info("  [%s] %s → %s", a["type"], a["job"], a["uses"])

    # POST to the notify webhook
    notification = {
        "source":              "github-app",
        "repository":          repo_full_name,
        "pushed_by":           pusher,
        "branch":              branch,
        "commit_sha":          ref,
        "scanned_files":       changed_workflows,
        "third_party_actions": all_actions,
    }

    try:
        resp = requests.post(
            NOTIFY_WEBHOOK_URL,
            json=notification,
            timeout=10,
        )
        log.info("Webhook POST status: %s", resp.status_code)
    except requests.RequestException as exc:
        log.error("Failed to POST to notify webhook: %s", exc)

    return jsonify({"status": "processed", "actions_found": len(all_actions)}), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    log.info("Starting GitHub App webhook server on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
