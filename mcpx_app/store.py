"""Artifact storage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

ROOT = Path.home() / ".local" / "share" / "mad" / "mcpx"


def _host_slug(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path or "unknown"
    return host.replace("/", "_")


def write_artifact(url: str, data: dict[str, Any]) -> Path:
    stamp = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H-%M-%SZ")
    path = ROOT / _host_slug(url)
    path.mkdir(parents=True, exist_ok=True)
    file_path = path / f"{stamp}.json"
    file_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return file_path
