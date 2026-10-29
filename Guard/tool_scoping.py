"""[DEFENCE 3] TOOL SCOPING в режиме "рубильника" (kill switch) для выбранных tools.

По умолчанию модель видит ВСЕ tools. Как только запуск "зашёл не туда" (сработал один из
триггеров), закрываются только tools из списка `close` (по умолчанию только send_email),
остальные продолжают работать. Так видно, что слой действует, и можно проверять дальше,
что ещё способна сделать модель с оставшимися tools. Чистый код, ноль токенов и задержки.

Триггеры (что считать "зашёл не туда"), набор задаётся в конструкторе:
  tainted       в контекст попал недоверенный контент (tool с untrusted_output, у вас fetch_url)
  private_read  агент прочитал приватные данные (tool с private_data, у вас read_file)
  trifecta      оба условия сразу: приватное прочитано И недоверенное попало в контекст
  deny          другой слой (например, слой 4) уже отклонил вызов tool

Что закрывать (параметр close):
  ("send_email",)               по умолчанию, один tool
  ("send_email", "fetch_url")   оба канала наружу
  None                          все tools

Рубильник проверяется в двух местах:
  filter_tools     перед каждым запросом к модели (что показываем)
  check_tool_call  перед каждым выполнением (если модель вызвала несколько tools за один шаг,
                   флаги в ctx обновляются после каждого вызова, поэтому следующий уже закрыт)

Подключение (agent.py, main()): ToolScopingGuard() ставим первым после AuditLogGuard.
Файл кладётся в папку Guard/.
"""
from __future__ import annotations

import sys

from guards import Decision, Guard

TRIGGERS = ("tainted", "private_read", "trifecta", "deny")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _spec_name(spec: dict) -> str:
    return spec.get("name") or spec.get("function", {}).get("name", "?")


class ToolScopingGuard(Guard):
    name = "tool_scoping"

    def __init__(self, *, triggers: tuple[str, ...] = ("tainted",),
                 close: tuple[str, ...] | None = ("send_email",)):
        unknown = set(triggers) - set(TRIGGERS)
        if unknown:
            raise ValueError(f"unknown triggers {sorted(unknown)}, expected from {TRIGGERS}")
        self.triggers = tuple(triggers)
        self.close = None if close is None else set(close)   # None = закрыть все
        self.tripped = False         # рубильник сработал (до конца запуска)
        self.denied = False          # какой-то слой отклонил вызов
        target = "ALL" if self.close is None else sorted(self.close)
        _log(f"[3  SCOPE]    init (all tools open by default; on {list(self.triggers)} "
             f"-> close: {target})")

    def _is_closed(self, name: str) -> bool:
        return self.tripped and (self.close is None or name in self.close)

    # Новый запуск: всё снова открыто.
    def check_input(self, text: str) -> str:
        self.tripped = False
        self.denied = False
        return text

    # Слушаем события, чтобы поймать trigger "deny" от других слоёв.
    def on_event(self, event: dict) -> None:
        if event.get("type") == "tool_call" and event.get("decision") == "deny":
            self.denied = True

    def _update(self, ctx) -> None:
        if self.tripped:
            return
        state = {
            "tainted": ctx.tainted,
            "private_read": ctx.private_read,
            "trifecta": ctx.private_read and ctx.tainted,
            "deny": self.denied,
        }
        for t in self.triggers:
            if state[t]:
                self.tripped = True
                target = "ALL tools" if self.close is None else sorted(self.close)
                _log(f"[3  SCOPE]    KILL SWITCH: trigger '{t}' -> closed: {target}")
                return

    # ---------------- [DEFENCE 3] ----------------
    def filter_tools(self, specs: list, ctx) -> list:
        self._update(ctx)
        visible = [s for s in specs if not self._is_closed(_spec_name(s))]
        hidden = [_spec_name(s) for s in specs if self._is_closed(_spec_name(s))]
        _log(f"[3  SCOPE]    step {ctx.step}: open: {[_spec_name(s) for s in visible] or 'none'}"
             f" | closed: {hidden or '-'}")
        return visible

    # Страховка: несколько вызовов за один шаг, или модель вызвала закрытый tool по памяти.
    def check_tool_call(self, name: str, args: dict, ctx) -> Decision:
        self._update(ctx)
        if self._is_closed(name):
            _log(f"[3  SCOPE]    {name}: closed by kill switch -> DENY")
            return Decision.deny(f"tool_scoping: {name} is closed for this run")
        return Decision.allow()