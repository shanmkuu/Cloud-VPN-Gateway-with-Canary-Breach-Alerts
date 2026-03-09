"""
canary_monitor.py – Async WireGuard Canary Breach Monitor
==========================================================
Author  : Lead Security Engineer
Purpose : Tail system logs for WireGuard authentication failures, apply a
          sliding-window threshold, enrich attacker IPs with GeoIP data, and
          dispatch a rich embed webhook alert to Discord or Slack.

Dependencies (see requirements.txt):
    asyncio (stdlib), watchfiles, httpx, rich, python-dotenv

Environment variables (.env):
    WEBHOOK_URL          – Discord or Slack webhook URL (required)
    WEBHOOK_TYPE         – "discord" | "slack" (default: discord)
    LOG_PATH             – Path to log file (default: /var/log/syslog)
    ALERT_THRESHOLD      – Failures before alert (default: 5)
    ALERT_WINDOW_SECS    – Sliding window in seconds (default: 120)
    GEOIP_API_URL        – GeoIP endpoint (default: ip-api.com/json)
    DRY_RUN              – Set to "1" to print alerts without sending (default: 0)

Usage:
    python src/canary_monitor.py
    python src/canary_monitor.py --log /var/log/syslog --threshold 3 --window 60
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# ── Environment Setup ──────────────────────────────────────────────────────────
load_dotenv()

console = Console()

# ── Regex Patterns ────────────────────────────────────────────────────────────
# Matches WireGuard kernel log lines indicating auth failure
# Examples:
#   wireguard: wg0: Invalid MAC1 from peer 203.0.113.42:4500
#   wireguard: wg0: Handshake failed from 203.0.113.42:4500
#   wireguard: wg0: Replay attack detected from 198.51.100.7:51820
WG_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"wireguard.*?(?:Invalid MAC1|invalid mac1).*?(?:from peer |from )?"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"wireguard.*?[Hh]andshake (?:failed|timed out|did not complete).*?"
        r"(?:from peer |from )?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"wireguard.*?[Rr]eplay attack.*?"
        r"(?:from peer |from )?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?",
        re.IGNORECASE,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# GeoIP Enrichment
# ─────────────────────────────────────────────────────────────────────────────
async def fetch_geoip(ip: str, client: httpx.AsyncClient) -> dict:
    """Fetch GeoIP metadata for an IP address using ip-api.com (free tier).

    Returns a dict with keys: country, regionName, city, isp, org, as, query.
    Falls back to placeholder data on any error to keep alerting non-blocking.
    """
    base_url = os.getenv("GEOIP_API_URL", "http://ip-api.com/json")
    fields = "status,country,regionName,city,isp,org,as,query,lat,lon,threat"
    url = f"{base_url}/{ip}?fields={fields}"
    try:
        resp = await client.get(url, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return data
    except (httpx.RequestError, httpx.HTTPStatusError, json.JSONDecodeError):
        pass
    return {
        "country": "Unknown",
        "regionName": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "as": "Unknown",
        "query": ip,
        "lat": 0,
        "lon": 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Webhook Dispatch
# ─────────────────────────────────────────────────────────────────────────────
def _build_discord_payload(ip: str, count: int, window: int, geo: dict) -> dict:
    """Construct a Discord Rich Embed webhook payload."""
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "username": "🛡️ WireGuard Canary",
        "avatar_url": "https://www.wireguard.com/img/wireguard.svg",
        "embeds": [
            {
                "title": "🚨 Canary Alert — WireGuard Breach Attempt Detected",
                "description": (
                    f"**{count}** authentication failures from a single source "
                    f"detected within a **{window}s** sliding window.\n\n"
                    f"CrowdSec has been notified and may have already blocked "
                    f"this IP."
                ),
                "color": 0xFF0000,  # Red
                "timestamp": timestamp,
                "thumbnail": {
                    "url": "https://iplocation.io/img/ip-location.svg"
                },
                "fields": [
                    {
                        "name": "🎯 Attacker IP",
                        "value": f"`{ip}`",
                        "inline": True,
                    },
                    {
                        "name": "🔢 Failure Count",
                        "value": f"**{count}** in {window}s",
                        "inline": True,
                    },
                    {
                        "name": "🌍 Country",
                        "value": geo.get("country", "Unknown"),
                        "inline": True,
                    },
                    {
                        "name": "🏙️ City / Region",
                        "value": (
                            f"{geo.get('city', 'N/A')}, "
                            f"{geo.get('regionName', 'N/A')}"
                        ),
                        "inline": True,
                    },
                    {
                        "name": "🏢 ISP / Org",
                        "value": geo.get("isp") or geo.get("org", "Unknown"),
                        "inline": True,
                    },
                    {
                        "name": "🔗 ASN",
                        "value": geo.get("as", "Unknown"),
                        "inline": True,
                    },
                    {
                        "name": "📍 Coordinates",
                        "value": (
                            f"{geo.get('lat', 0):.4f}, {geo.get('lon', 0):.4f}"
                        ),
                        "inline": True,
                    },
                    {
                        "name": "⏰ Detected At",
                        "value": f"<t:{int(time.time())}:F>",
                        "inline": True,
                    },
                    {
                        "name": "⚡ Recommended Action",
                        "value": (
                            "`cscli decisions add --ip "
                            f"{ip} --duration 24h --type ban`"
                        ),
                        "inline": False,
                    },
                ],
                "footer": {
                    "text": "WireGuard Canary Monitor • NIST SP 800-77",
                    "icon_url": "https://crowdsec.net/favicon.ico",
                },
            }
        ],
    }


def _build_slack_payload(ip: str, count: int, window: int, geo: dict) -> dict:
    """Construct a Slack Block Kit webhook payload."""
    return {
        "text": f":rotating_light: WireGuard Alert: {count} failures from `{ip}`",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 WireGuard Canary — Breach Attempt",
                    "emoji": True,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Attacker IP:*\n`{ip}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Failures:*\n{count} in {window}s",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Country:*\n{geo.get('country', 'Unknown')}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"*ISP:*\n{geo.get('isp') or geo.get('org', 'Unknown')}"
                        ),
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*City:*\n{geo.get('city', 'N/A')}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*ASN:*\n{geo.get('as', 'Unknown')}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f":hammer: *Ban command:*\n"
                        f"```cscli decisions add --ip {ip} --duration 24h --type ban```"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"WireGuard Canary Monitor • "
                            f"<!date^{int(time.time())}^{{date_time}}|Now>"
                        ),
                    }
                ],
            },
        ],
    }


async def send_webhook_alert(
    ip: str,
    count: int,
    window: int,
    geo: dict,
    client: httpx.AsyncClient,
) -> None:
    """Send a rich embed alert to the configured webhook endpoint."""
    webhook_url = os.getenv("WEBHOOK_URL", "")
    webhook_type = os.getenv("WEBHOOK_TYPE", "discord").lower()
    dry_run = os.getenv("DRY_RUN", "0") == "1"

    if webhook_type == "slack":
        payload = _build_slack_payload(ip, count, window, geo)
    else:
        payload = _build_discord_payload(ip, count, window, geo)

    if dry_run or not webhook_url:
        console.print(
            Panel(
                Text(json.dumps(payload, indent=2), style="bold yellow"),
                title="[DRY RUN] Webhook Payload",
                border_style="yellow",
            )
        )
        return

    try:
        resp = await client.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        resp.raise_for_status()
        console.print(
            f"[bold green]✓[/] Alert sent to {webhook_type.capitalize()} "
            f"for IP [cyan]{ip}[/] — HTTP {resp.status_code}"
        )
    except httpx.HTTPError as exc:
        console.print(
            f"[bold red]✗[/] Failed to send webhook alert: {exc}",
            style="red",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Sliding-Window Failure Tracker
# ─────────────────────────────────────────────────────────────────────────────
class FailureTracker:
    """Per-IP sliding window for failure event counting.

    Uses a deque of timestamps per source IP. Events outside the window are
    expired on each check to keep memory usage bounded.
    """

    def __init__(self, threshold: int, window_secs: int) -> None:
        self.threshold = threshold
        self.window_secs = window_secs
        # ip → deque of UNIX timestamps
        self._events: defaultdict[str, deque] = defaultdict(deque)
        # IPs that have already triggered an alert (cooldown)
        self._alerted: dict[str, float] = {}

    def record(self, ip: str) -> int:
        """Record a failure for *ip*. Returns current count in the window."""
        now = time.monotonic()
        cutoff = now - self.window_secs
        q = self._events[ip]
        q.append(now)
        # Expire old events
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def should_alert(self, ip: str) -> bool:
        """Return True if count >= threshold and cooldown has expired."""
        count = len(self._events[ip])
        if count < self.threshold:
            return False
        # Cooldown: don't re-alert for the same IP within the window
        last = self._alerted.get(ip, 0.0)
        if time.monotonic() - last < self.window_secs:
            return False
        return True

    def mark_alerted(self, ip: str) -> None:
        self._alerted[ip] = time.monotonic()
        self._events[ip].clear()  # Reset counter after alert

    @property
    def current_counts(self) -> dict[str, int]:
        now = time.monotonic()
        cutoff = now - self.window_secs
        result = {}
        for ip, q in self._events.items():
            # Inline expire for display purposes
            count = sum(1 for t in q if t >= cutoff)
            if count:
                result[ip] = count
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Log File Tail
# ─────────────────────────────────────────────────────────────────────────────
def extract_ip_from_line(line: str) -> Optional[str]:
    """Try each WireGuard pattern against *line* and return the first IP match."""
    for pattern in WG_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group("ip")
    return None


async def tail_log_file(
    log_path: Path,
    line_queue: asyncio.Queue,
) -> None:
    """Watch a log file using watchfiles and yield new lines via *line_queue*.

    Falls back to polling if watchfiles cannot watch the file directly
    (e.g., when the file is written by rsyslog via inotify-incompatible FS).
    """
    try:
        from watchfiles import awatch
    except ImportError:
        console.print(
            "[yellow]watchfiles not found — falling back to polling (1s)[/]"
        )
        await _poll_tail(log_path, line_queue)
        return

    console.print(
        f"[bold blue]→[/] Watching [cyan]{log_path}[/] with watchfiles..."
    )

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # Seek to end — don't replay history
        async for _ in awatch(log_path):
            while True:
                line = fh.readline()
                if not line:
                    break
                await line_queue.put(line.rstrip())


async def _poll_tail(log_path: Path, line_queue: asyncio.Queue) -> None:
    """Fallback: poll the log file every second for new data."""
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                await line_queue.put(line.rstrip())
            else:
                await asyncio.sleep(1)


# ─────────────────────────────────────────────────────────────────────────────
# Main Event Loop
# ─────────────────────────────────────────────────────────────────────────────
async def process_events(
    line_queue: asyncio.Queue,
    tracker: FailureTracker,
    http_client: httpx.AsyncClient,
) -> None:
    """Consume lines from *line_queue*, detect thresholds, and fire alerts."""
    while True:
        line = await line_queue.get()
        ip = extract_ip_from_line(line)
        if not ip:
            continue

        count = tracker.record(ip)

        console.print(
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
            f"[red]●[/] Failure from [cyan]{ip}[/] — "
            f"count={count}/{tracker.threshold} in {tracker.window_secs}s window"
        )

        if tracker.should_alert(ip):
            tracker.mark_alerted(ip)
            console.print(
                f"\n[bold red]🚨 THRESHOLD BREACHED[/] — "
                f"[cyan]{ip}[/] ({count} failures). "
                f"Fetching GeoIP & sending alert...\n"
            )
            geo = await fetch_geoip(ip, http_client)
            await send_webhook_alert(
                ip=ip,
                count=count,
                window=tracker.window_secs,
                geo=geo,
                client=http_client,
            )


async def main(args: argparse.Namespace) -> None:
    log_path = Path(args.log)
    if not log_path.exists():
        console.print(
            f"[red]✗[/] Log file not found: [cyan]{log_path}[/]\n"
            "  Hint: run as root or check LOG_PATH in .env",
            highlight=False,
        )
        sys.exit(1)

    tracker = FailureTracker(
        threshold=args.threshold,
        window_secs=args.window,
    )

    console.print(
        Panel(
            Text.assemble(
                ("WireGuard Canary Monitor\n", "bold white"),
                (f"  Log      : {log_path}\n", "cyan"),
                (f"  Threshold: {args.threshold} failures\n", "cyan"),
                (f"  Window   : {args.window}s\n", "cyan"),
                (
                    f"  Webhook  : "
                    f"{'[DRY RUN]' if os.getenv('DRY_RUN') == '1' else 'LIVE'}\n",
                    "yellow",
                ),
            ),
            title="[bold green]🛡️ Canary Active[/]",
            border_style="green",
        )
    )

    line_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)

    async with httpx.AsyncClient(
        headers={"User-Agent": "WireGuard-Canary/1.0"},
        follow_redirects=True,
    ) as client:
        await asyncio.gather(
            tail_log_file(log_path, line_queue),
            process_events(line_queue, tracker, client),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WireGuard Canary Monitor — async log watcher with GeoIP alerts"
    )
    parser.add_argument(
        "--log",
        default=os.getenv("LOG_PATH", "/var/log/syslog"),
        help="Path to the log file to monitor (default: /var/log/syslog)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=int(os.getenv("ALERT_THRESHOLD", "5")),
        help="Number of failures before alerting (default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=int(os.getenv("ALERT_WINDOW_SECS", "120")),
        help="Sliding window in seconds (default: 120)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Canary monitor stopped.[/]")
