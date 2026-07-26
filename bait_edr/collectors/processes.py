"""Cross-platform process telemetry collector."""

from __future__ import annotations

import psutil

from bait_edr.collectors.base import Collector
from bait_edr.models import EndpointEvent


class ProcessCollector(Collector):
    """Emit process start observations based on PID and creation time."""

    def __init__(self, capture_command_line: bool = True, capture_username: bool = True) -> None:
        self.capture_command_line = capture_command_line
        self.capture_username = capture_username
        self._seen: set[tuple[int, float]] = set()

    def collect(self) -> list[EndpointEvent]:
        events: list[EndpointEvent] = []
        current: set[tuple[int, float]] = set()
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            try:
                info = proc.info
                identity = (int(info["pid"]), float(info.get("create_time") or 0.0))
                current.add(identity)
                if identity in self._seen:
                    continue
                cmdline = " ".join(info.get("cmdline") or []) if self.capture_command_line else ""
                username = info.get("username") if self.capture_username else None
                parent_name = ""
                try:
                    parent = proc.parent()
                    parent_name = parent.name() if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                events.append(
                    EndpointEvent(
                        category="process",
                        action="start",
                        outcome="success",
                        user={"name": username} if username else {},
                        process={
                            "pid": info["pid"],
                            "ppid": info.get("ppid"),
                            "name": info.get("name") or "",
                            "executable": info.get("exe") or "",
                            "command_line": cmdline,
                            "create_time": info.get("create_time"),
                            "parent_name": parent_name,
                        },
                        metadata={"collector": "psutil.processes"},
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self._seen = current
        return events
