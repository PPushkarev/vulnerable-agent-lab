"""Интерфейс защитного слоя. Каждый слой защиты = подкласс Guard.

Точки подключения:
  A (сборка контекста): system_prompt, wrap_untrusted
  B (граница модели):   check_input, check_output
  C (выполнение tool):  check_tool_call, check_tool_result
  Наблюдение:           on_event (слой 6, мониторинг)

Все методы по умолчанию ничего не меняют, поэтому без гардов агент уязвим (baseline).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import config


class Blocked(Exception):
    """Guard бросает это, чтобы остановить весь запуск (блок входа/выхода)."""

    def __init__(self, reason: str, guard: str = "?"):
        super().__init__(reason)
        self.reason = reason
        self.guard = guard


@dataclass
class Decision:
    action: str = "allow"   # allow | deny | approve (нужно одобрение человека)
    reason: str = ""
    guard: str = ""

    @classmethod
    def allow(cls) -> "Decision":
        return cls("allow")

    @classmethod
    def deny(cls, reason: str) -> "Decision":
        return cls("deny", reason)

    @classmethod
    def approve(cls, reason: str) -> "Decision":
        return cls("approve", reason)


class Guard:
    name = "guard"

    # --- A: сборка контекста ---
    def system_prompt(self, prompt: str) -> str:
        return prompt

    def wrap_untrusted(self, text: str, source: str) -> str:
        """Результат инструмента перед попаданием в контекст (разделители, пометки)."""
        return text

    # --- B: граница модели ---
    def check_input(self, text: str) -> str:
        """Ввод пользователя. Верни текст (можно изменённый) или брось Blocked."""
        return text

    def check_output(self, text: str) -> str:
        """Финальный ответ агента. Верни текст или брось Blocked."""
        return text

    # --- C: выполнение инструмента ---
    def check_tool_call(self, name: str, args: dict, ctx: Any) -> Decision:
        return Decision.allow()

    def check_tool_result(self, name: str, args: dict, result: str) -> str:
        """Результат инструмента до попадания в контекст (фильтры, редакция)."""
        return result

    # --- наблюдение ---
    def on_event(self, event: dict) -> None:
        pass

    def filter_tools(self, specs, ctx):
        return specs

class AuditLogGuard(Guard):
    """Пишет все события запуска в JSONL (основа слоя 6 и оценки тестов)."""

    name = "audit_log"

    def __init__(self, path=None):
        self.path = path or (config.LOGS / "audit.jsonl")

    def on_event(self, event: dict) -> None:
        rec = {"ts": round(time.time(), 3), **event}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
