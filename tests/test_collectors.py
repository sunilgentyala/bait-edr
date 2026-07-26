from types import SimpleNamespace

import psutil

from bait_edr.collectors.network import NetworkCollector
from bait_edr.collectors.processes import ProcessCollector


class FakeProcess:
    def __init__(self, pid: int, name: str = "demo.exe") -> None:
        self.pid = pid
        self._name = name
        self.info = {
            "pid": pid,
            "ppid": 10,
            "name": name,
            "exe": f"/opt/{name}",
            "cmdline": [name, "--safe-test"],
            "username": "tester",
            "create_time": 100.0,
        }

    def name(self) -> str:
        return self._name

    def parent(self):
        return FakeProcess(10, "parent.exe")


def test_network_collector_does_not_invent_direction(monkeypatch) -> None:
    connection = SimpleNamespace(
        pid=42,
        laddr=SimpleNamespace(ip="10.0.0.10", port=50123),
        raddr=SimpleNamespace(ip="192.0.2.10", port=4444),
        status=psutil.CONN_ESTABLISHED,
    )
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProcess(pid))

    events = NetworkCollector().collect()

    assert len(events) == 1
    assert events[0].network["direction"] == "unknown"
    assert events[0].metadata["direction_confidence"] == "unavailable_from_snapshot"


def test_process_collector_enriches_parent_name(monkeypatch) -> None:
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [FakeProcess(42)])

    events = ProcessCollector().collect()

    assert len(events) == 1
    assert events[0].process["parent_name"] == "parent.exe"
    assert events[0].process["command_line"] == "demo.exe --safe-test"
