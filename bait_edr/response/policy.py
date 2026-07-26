"""Response policy evaluation."""

from __future__ import annotations

from pathlib import Path

from bait_edr.config import ResponseConfig


class ResponsePolicy:
    def __init__(self, config: ResponseConfig) -> None:
        self.config = config

    @property
    def active(self) -> bool:
        return self.config.mode.lower() == "active"

    def may_terminate(self, process_name: str) -> tuple[bool, str]:
        normalized = process_name.lower().strip()
        protected = {name.lower().strip() for name in self.config.protected_process_names}
        if normalized in protected:
            return False, f"Process {process_name} is protected"
        if not self.active:
            return False, "Response mode is audit"
        if not self.config.allow_process_termination:
            return False, "Process termination is disabled"
        return True, "Process termination allowed by policy"

    def may_quarantine(self, file_path: str) -> tuple[bool, str]:
        target = Path(file_path).expanduser().resolve()
        if not self.active:
            return False, "Response mode is audit"
        if not self.config.allow_file_quarantine:
            return False, "File quarantine is disabled"
        roots = [Path(root).expanduser().resolve() for root in self.config.allowed_quarantine_roots]
        if not any(target == root or root in target.parents for root in roots):
            return False, "File path is outside approved quarantine roots"
        return True, "File quarantine allowed by policy"
