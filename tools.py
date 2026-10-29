"""Инструменты агента. Все фейковые и безопасные для хоста:
файлы только внутри sandbox/, сеть только на локальный мок-сервер, почта пишется в лог.

Флаги у каждого инструмента нужны политикам (слой 4) для модели "смертельной тройки":
  private_data     читает приватные данные
  untrusted_output возвращает недоверенный контент (веб, чужие документы)
  exfil_channel    может отправить данные наружу
"""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import config


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    fn: Callable[..., str]
    private_data: bool = False
    untrusted_output: bool = False
    exfil_channel: bool = False


def _resolve(rel: str) -> Path:
    """Путь строго внутри sandbox (защита хоста, а не слой защиты агента)."""
    p = (config.SANDBOX / rel).resolve()
    if p != config.SANDBOX and config.SANDBOX not in p.parents:
        raise ValueError("path outside workspace")
    return p


def list_files(path: str = ".") -> str:
    p = _resolve(path)
    if not p.is_dir():
        return f"ERROR: not a directory: {path}"
    names = sorted(x.name + ("/" if x.is_dir() else "") for x in p.iterdir())
    return "\n".join(names) or "(empty)"


def read_file(path: str) -> str:
    p = _resolve(path)
    if not p.is_file():
        return f"ERROR: file not found: {path}"
    return p.read_text(encoding="utf-8", errors="replace")[: config.MAX_TOOL_OUTPUT]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch_url(url: str) -> str:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or (u.hostname or "") not in config.ALLOWED_HOSTS:
        return f"ERROR: host not reachable in lab: {u.hostname}"
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(url, timeout=5) as r:
            return r.read(config.MAX_TOOL_OUTPUT).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {e}"


def send_email(to: str, subject: str, body: str) -> str:
    rec = {"ts": round(time.time(), 3), "to": to, "subject": subject, "body": body}
    with open(config.LOGS / "outbox.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return f"Email sent to {to}"


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required,
            "additionalProperties": False}


TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("list_files", "List files in a workspace folder.",
         _schema({"path": {"type": "string", "description": "Folder relative to workspace, default '.'"}}, []),
         list_files),
    Tool("read_file", "Read a text file from the workspace.",
         _schema({"path": {"type": "string", "description": "File path relative to workspace"}}, ["path"]),
         read_file, private_data=True),
    Tool("fetch_url", "Fetch a web page by URL and return its text.",
         _schema({"url": {"type": "string"}}, ["url"]),
         fetch_url, untrusted_output=True, exfil_channel=True),
    Tool("send_email", "Send an email.",
         _schema({"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
                 ["to", "subject", "body"]),
         send_email, exfil_channel=True),
]}


def openai_specs() -> list[dict]:
    """Описание инструментов в формате OpenAI Responses API."""
    return [{"type": "function", "name": t.name, "description": t.description,
             "parameters": t.parameters, "strict": False} for t in TOOLS.values()]


def run_tool(name: str, args: dict) -> str:
    tool = TOOLS.get(name)
    if tool is None:
        return f"ERROR: unknown tool {name}"
    try:
        return str(tool.fn(**args))
    except TypeError as e:
        return f"ERROR: bad arguments: {e}"
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {e}"
