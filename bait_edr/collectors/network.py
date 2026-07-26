"""Cross-platform network connection collector."""

from __future__ import annotations

import psutil

from bait_edr.collectors.base import Collector
from bait_edr.models import EndpointEvent


class NetworkCollector(Collector):
    """Emit newly observed established TCP connection snapshots.

    The portable psutil API does not reliably identify whether an established
    connection was initiated locally. The collector therefore reports direction
    as ``unknown`` instead of making an unsafe outbound or inbound assumption.
    Native operating-system collectors can provide a verified direction later.
    """

    def __init__(self) -> None:
        self._seen: set[tuple] = set()

    def collect(self) -> list[EndpointEvent]:
        events: list[EndpointEvent] = []
        current: set[tuple] = set()
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            return events

        for conn in connections:
            if not conn.raddr or conn.status != psutil.CONN_ESTABLISHED:
                continue
            local_ip, local_port = conn.laddr.ip, conn.laddr.port
            remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
            identity = (conn.pid, local_ip, local_port, remote_ip, remote_port)
            current.add(identity)
            if identity in self._seen:
                continue
            process_name = ""
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            events.append(
                EndpointEvent(
                    category="network",
                    action="connection",
                    outcome="success",
                    process={"pid": conn.pid, "name": process_name},
                    network={
                        "protocol": "tcp",
                        "direction": "unknown",
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": conn.status,
                    },
                    metadata={
                        "collector": "psutil.network",
                        "direction_confidence": "unavailable_from_snapshot",
                    },
                )
            )
        self._seen = current
        return events
