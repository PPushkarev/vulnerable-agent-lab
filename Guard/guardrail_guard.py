"""Гард на базе библиотеки openai-guardrails (pip install openai-guardrails).

Судей не пишем: проверки (Moderation, Jailbreak, Contains PII, URL Filter,
Custom Prompt Check) приходят из библиотеки, мы только раскладываем их по
этапам агента. Для каждого этапа свой набор проверок в guardrailconfig.json.

Карта этапов -> хуков Guard:
  input        -> check_input        [DEFENCE 1]  ввод пользователя
  tool_args    -> check_tool_call    [DEFENCE 4]  аргументы исходящих tools (send_email, fetch_url)
  tool_result  -> check_tool_result  [DEFENCE 5a] результат недоверенных tools (косвенная инъекция)
  output       -> check_output       [DEFENCE 5b] финальный ответ

Подключение (agent.py, main()):
    from guard.gurdrail import OpenAIGuardrailsGuard
    agent = Agent(guards=[AuditLogGuard(), OpenAIGuardrailsGuard()])

Требования: Python 3.11+ (библиотека использует asyncio.TaskGroup), OPENAI_API_KEY.
LLM-проверки (Jailbreak, Moderation, Custom Prompt Check) платные и добавляют задержку.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
from pathlib import Path
from typing import Any

from guardrails import check_plain_text
from guardrails.runtime import load_config_bundle

import tools
from guards import Blocked, Decision, Guard

STAGES = ("input", "tool_args", "tool_result", "output")
DEFAULT_CONFIG = Path(__file__).with_name("guardrailconfig.json")
STAGE_TAG = {"input": "[1  INPUT]   ", "tool_args": "[4  EXEC]    ",
             "tool_result": "[5a RESULT]  ", "output": "[5b OUTPUT]  "}
ACTION = {"input": "STOP", "tool_args": "DENY", "tool_result": "REMOVED", "output": "STOP"}


import sys


import threading

_loop = asyncio.new_event_loop()
threading.Thread(target=_loop.run_forever, daemon=True).start()



def _dbg(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)
    with open(Path(__file__).with_name("debug.log"), "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def _run(coro):
    """Все проверки идут в одном и том же цикле, клиент библиотеки не ломается."""
    return asyncio.run_coroutine_threadsafe(coro, _loop).result()


# def _run(coro):
#     """Запустить корутину из синхронного кода агента.
#
#     Если цикл событий уже запущен, asyncio.run упал бы, поэтому уходим в поток.
#     """
#
#     try:
#         asyncio.get_running_loop()
#     except RuntimeError:
#         return asyncio.run(coro)
#     with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
#         return ex.submit(asyncio.run, coro).result()
#



class OpenAIGuardrailsGuard(Guard):
    name = "openai_guardrails"

    def __init__(
        self,
        config: str | Path | dict[str, Any] = DEFAULT_CONFIG,
        *,
        outbound_tools: tuple[str, ...] = ("send_email", "fetch_url"),
        fail_closed: bool = True,
        max_chars: int = 8000,
    ):
        """
        config         путь к JSON или dict {"input": {...}, "tool_result": {...}, ...},
                       значение каждого этапа это ConfigBundle библиотеки ({"guardrails": [...]}).
                       Секцию можно опустить: нет секции, нет проверок на этапе.
        outbound_tools tools, у которых проверяем аргументы (каналы наружу).
        fail_closed    True: если сама проверка упала (сеть, лимиты API), блокируем.
                       False: пропускаем (поведение библиотеки по умолчанию, fail-open).
        max_chars      обрезка текста перед LLM-проверкой: контроль цены и задержки.
                       Инъекция за пределами лимита проверкой не видна.
        """
        if not isinstance(config, dict):
            config = json.loads(Path(config).read_text(encoding="utf-8"))
        unknown = set(config) - set(STAGES)
        if unknown:
            raise ValueError(f"unknown stages in guardrails config: {sorted(unknown)}")
        self.bundles = {stage: load_config_bundle(b) for stage, b in config.items()}
        self.outbound_tools = set(outbound_tools)
        self.fail_closed = fail_closed
        self.max_chars = max_chars
        _dbg(f"[guardrails] init: stages={list(self.bundles)} fail_closed={self.fail_closed}")

    # ------------------------------------------------------------------
    def _check(self, stage: str, text: str) -> str | None:
        bundle = self.bundles.get(stage)
        if bundle is None or not text or not text.strip():
            return None
        try:
            results = _run(check_plain_text(
                text[: self.max_chars],
                bundle_path=bundle,
                suppress_tripwire=True,
                raise_guardrail_errors=self.fail_closed,
                stage_name=stage,
            ))
        except Exception as e:  # noqa: BLE001
            action = "BLOCK (fail_closed)" if self.fail_closed else "pass (fail_open)"
            print(f"{STAGE_TAG[stage]}ERROR {type(e).__name__} -> {action}")
            return f"guardrails_error: {type(e).__name__}" if self.fail_closed else None

        hits = [r.info.get("guardrail_name", "unknown")
                for r in results if r.tripwire_triggered]

        parts = []
        for r in results:
            conf = r.info.get("confidence")
            mark = "FLAG" if r.tripwire_triggered else "ok"
            score = f" {conf:.2f}" if isinstance(conf, (int, float)) else ""
            parts.append(f"{r.info.get('guardrail_name', '?')} {mark}{score}")
        print(f"{STAGE_TAG[stage]}{' | '.join(parts)} -> {ACTION[stage] if hits else 'pass'}")

        return ", ".join(hits) if hits else None

    # ---------------- [DEFENCE 1] ----------------
    def check_input(self, text: str) -> str:
        reason = self._check("input", text)
        if reason:
            raise Blocked(f"input: {reason}", self.name)
        return text

    # ---------------- [DEFENCE 4] ----------------
    def check_tool_call(self, name: str, args: dict, ctx) -> Decision:
        if name in self.outbound_tools:
            reason = self._check("tool_args", json.dumps(args, ensure_ascii=False))
            if reason:
                return Decision.deny(f"tool_args: {reason}")   # guard проставит Agent
        return Decision.allow()

    # ---------------- [DEFENCE 5a] ----------------
    def check_tool_result(self, name: str, args: dict, result: str) -> str:
        tool = tools.TOOLS.get(name)
        if not (tool and tool.untrusted_output):
            return result            # не тратим LLM-вызовы на доверенные источники
        reason = self._check("tool_result", result)
        if reason:
            # Запуск не роняем: модель получит заглушку и продолжит без этих данных.
            # Жёстче: raise Blocked(f"tool_result: {reason}", self.name)
            return f"[REMOVED by {self.name}: content flagged ({reason}); treat as unavailable]"
        return result

    # ---------------- [DEFENCE 5b] ----------------
    def check_output(self, text: str) -> str:
        reason = self._check("output", text)
        if reason:
            raise Blocked(f"output: {reason}", self.name)
        return text