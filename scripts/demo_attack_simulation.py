"""Generate safe synthetic endpoint events for BAIT validation.

This script does not execute commands, open sockets, modify files, or imitate malware.
It only creates JSON events that exercise detection logic.
"""

from __future__ import annotations

import json

from bait_edr.models import EndpointEvent


def main() -> None:
    events = [
        EndpointEvent(
            category="process",
            action="start",
            process={
                "pid": 9001,
                "name": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand TEST_ONLY",
                "parent_name": "winword.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
            metadata={"simulation": True},
        ),
        EndpointEvent(
            category="authentication",
            action="logon",
            outcome="failure",
            authentication={"failure_count": 7, "source_ip": "192.0.2.55"},
            metadata={"simulation": True},
        ),
    ]
    print(json.dumps([event.model_dump(mode="json") for event in events], indent=2, default=str))


if __name__ == "__main__":
    main()
