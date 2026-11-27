"""
Alerting & Notification Service
Supports: Email (SMTP) and Slack (Incoming Webhook)

Design principles:
- Notification failures NEVER break incident creation or rotation.
- Raw secrets are NEVER included in notifications.
- Duplicate notifications are suppressed using a simple in-memory dedup set.
- Each channel is independently toggled via environment variables.
"""

import logging
import smtplib
import json
import hashlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional
from datetime import datetime, timezone

import httpx

from app.config.settings import settings

logger = logging.getLogger(__name__)

# ── In-memory deduplication (incident_id + channel) ──────────────────────────
_sent_notifications: set = set()


def _dedup_key(incident_id: str, channel: str, event: str) -> str:
    raw = f"{incident_id}:{channel}:{event}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Email Notification ────────────────────────────────────────────────────────

def send_email_alert(
    incident_id: str,
    repository: str,
    severity: str,
    detector_name: str,
    file_path: str,
    event: str = "incident_detected",
    extra_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send an email alert for a detected security incident or rotation event.
    Raw secret values are never included.
    """
    if not settings.ALERT_EMAIL_ENABLED:
        return {"success": False, "skipped": True, "reason": "email_disabled"}

    dedup = _dedup_key(incident_id, "email", event)
    if dedup in _sent_notifications:
        return {"success": True, "skipped": True, "reason": "already_sent"}

    subject_map = {
        "incident_detected": f"🚨 [{severity}] Secret Detected – {repository}",
        "rotation_success": f"✅ Credential Rotated – Incident {incident_id}",
        "rotation_failed": f"❌ Rotation Failed – Incident {incident_id}",
    }
    subject = subject_map.get(event, f"GitOps Secret Shield Alert – {incident_id}")

    body_lines = [
        "GitOps Secret Shield – Security Alert",
        "=" * 50,
        f"Incident ID  : {incident_id}",
        f"Event        : {event}",
        f"Repository   : {repository}",
        f"Severity     : {severity}",
        f"Detector     : {detector_name}",
        f"File         : {file_path}",
        f"Timestamp    : {datetime.now(timezone.utc).isoformat()}",
    ]
    if extra_notes:
        body_lines.append(f"Notes        : {extra_notes}")
    body_lines += [
        "",
        "⚠️  Raw credential values are NEVER included in alerts.",
        "    Review the Security Dashboard for full incident details.",
    ]
    body = "\n".join(body_lines)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.ALERT_EMAIL_FROM
        msg["To"] = settings.ALERT_EMAIL_TO
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(settings.ALERT_SMTP_HOST, settings.ALERT_SMTP_PORT, timeout=10) as smtp:
            if settings.ALERT_SMTP_TLS:
                smtp.starttls()
            if settings.ALERT_SMTP_USER and settings.ALERT_SMTP_PASS:
                smtp.login(settings.ALERT_SMTP_USER, settings.ALERT_SMTP_PASS)
            smtp.sendmail(settings.ALERT_EMAIL_FROM, [settings.ALERT_EMAIL_TO], msg.as_string())

        _sent_notifications.add(dedup)
        logger.info(f"[Alert-Email] Sent '{event}' notification for {incident_id}")
        return {"success": True, "channel": "email", "incident_id": incident_id}

    except Exception as exc:
        # Notification failures must NOT propagate to callers
        logger.warning(f"[Alert-Email] Failed to send notification for {incident_id}: {exc}")
        return {"success": False, "channel": "email", "error": str(exc), "incident_id": incident_id}


# ── Slack Notification ────────────────────────────────────────────────────────

def send_slack_alert(
    incident_id: str,
    repository: str,
    severity: str,
    detector_name: str,
    file_path: str,
    event: str = "incident_detected",
    extra_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a Slack notification via Incoming Webhook.
    Raw secret values are never included.
    """
    if not settings.ALERT_SLACK_ENABLED:
        return {"success": False, "skipped": True, "reason": "slack_disabled"}

    if not settings.ALERT_SLACK_WEBHOOK_URL:
        return {"success": False, "skipped": True, "reason": "slack_webhook_not_configured"}

    dedup = _dedup_key(incident_id, "slack", event)
    if dedup in _sent_notifications:
        return {"success": True, "skipped": True, "reason": "already_sent"}

    emoji_map = {
        "incident_detected": "🚨",
        "rotation_success": "✅",
        "rotation_failed": "❌",
    }
    emoji = emoji_map.get(event, "⚠️")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} GitOps Secret Shield Alert"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Event:*\n{event}"},
                {"type": "mrkdwn", "text": f"*Incident ID:*\n{incident_id}"},
                {"type": "mrkdwn", "text": f"*Repository:*\n{repository}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                {"type": "mrkdwn", "text": f"*Detector:*\n{detector_name}"},
                {"type": "mrkdwn", "text": f"*File:*\n{file_path}"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
                        "| Raw secrets are NEVER included in alerts."
                    ),
                }
            ],
        },
    ]
    if extra_notes:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Notes:* {extra_notes}"},
        })

    payload = {"blocks": blocks}

    for attempt in range(1, 4):   # up to 3 retries
        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(
                    settings.ALERT_SLACK_WEBHOOK_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
            if res.status_code == 200:
                _sent_notifications.add(dedup)
                logger.info(f"[Alert-Slack] Sent '{event}' notification for {incident_id} (attempt {attempt})")
                return {"success": True, "channel": "slack", "incident_id": incident_id}
            else:
                logger.warning(
                    f"[Alert-Slack] HTTP {res.status_code} on attempt {attempt} for {incident_id}: {res.text}"
                )
        except Exception as exc:
            logger.warning(f"[Alert-Slack] Attempt {attempt} failed for {incident_id}: {exc}")

    return {
        "success": False,
        "channel": "slack",
        "error": f"All {3} attempts failed.",
        "incident_id": incident_id,
    }


# ── Unified Dispatch ──────────────────────────────────────────────────────────

def dispatch_alert(
    incident_id: str,
    repository: str,
    severity: str,
    detector_name: str,
    file_path: str,
    event: str = "incident_detected",
    extra_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dispatch alert to all configured channels.
    Safe: failures in one channel do not affect the other.
    """
    email_result = send_email_alert(
        incident_id=incident_id,
        repository=repository,
        severity=severity,
        detector_name=detector_name,
        file_path=file_path,
        event=event,
        extra_notes=extra_notes,
    )
    slack_result = send_slack_alert(
        incident_id=incident_id,
        repository=repository,
        severity=severity,
        detector_name=detector_name,
        file_path=file_path,
        event=event,
        extra_notes=extra_notes,
    )
    return {
        "email": email_result,
        "slack": slack_result,
    }
