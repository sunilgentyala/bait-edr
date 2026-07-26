"""Low-regret response actions with evidence preservation."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import psutil

from bait_edr.config import ResponseConfig
from bait_edr.file_scanner import FileScanner
from bait_edr.models import Alert, ResponseResult
from bait_edr.response.policy import ResponsePolicy


class ResponseManager:
    def __init__(self, config: ResponseConfig) -> None:
        self.config = config
        self.policy = ResponsePolicy(config)
        self.scanner = FileScanner()

    @staticmethod
    def _policy_status(reason: str) -> str:
        if reason in {
            "Response mode is audit",
            "Process termination is disabled",
            "File quarantine is disabled",
        }:
            return "planned"
        return "blocked"

    def execute(self, alert: Alert, action: str) -> ResponseResult:
        dispatch = {
            "collect_triage": self.collect_triage,
            "terminate_process": self.terminate_process,
            "quarantine_file": self.quarantine_file,
            "isolate_host": self.isolate_host,
            "block_indicator": self.block_indicator,
        }
        handler = dispatch.get(action)
        if handler is None:
            return ResponseResult(
                alert_id=alert.alert_id,
                action=action,
                status="blocked",
                message="Unknown response action",
            )
        return handler(alert)

    def collect_triage(self, alert: Alert) -> ResponseResult:
        evidence = {
            "host": alert.event.host,
            "platform": alert.event.platform,
            "event_id": alert.event.event_id,
            "process": alert.event.process,
            "file": alert.event.file,
            "network": alert.event.network,
            "rule_id": alert.rule_id,
        }
        return ResponseResult(
            alert_id=alert.alert_id,
            action="collect_triage",
            status="executed",
            message="Triage evidence collected from the triggering event",
            evidence=evidence,
        )

    def terminate_process(self, alert: Alert) -> ResponseResult:
        pid = alert.event.process.get("pid")
        reported_name = str(alert.event.process.get("name") or "")
        if not isinstance(pid, int) or pid <= 1 or pid == os.getpid():
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status="blocked",
                message="A valid non-system target PID was not present",
            )

        allowed, reason = self.policy.may_terminate(reported_name)
        if not allowed:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status=self._policy_status(reason),
                message=reason,
                evidence={"pid": pid, "name": reported_name},
            )

        try:
            process = psutil.Process(pid)
            actual_name = process.name()
            actual_created = process.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status="failed",
                message=str(exc),
                evidence={"pid": pid, "name": reported_name},
            )

        if reported_name and actual_name.casefold() != reported_name.casefold():
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status="blocked",
                message="Target process identity changed before response execution",
                evidence={"pid": pid, "reported_name": reported_name, "actual_name": actual_name},
            )

        reported_created = alert.event.process.get("create_time")
        if (
            isinstance(reported_created, (int, float))
            and abs(actual_created - float(reported_created)) > 1.0
        ):
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status="blocked",
                message="Target PID was reused before response execution",
                evidence={
                    "pid": pid,
                    "reported_create_time": reported_created,
                    "actual_create_time": actual_created,
                },
            )

        allowed, reason = self.policy.may_terminate(actual_name)
        if not allowed:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status=self._policy_status(reason),
                message=reason,
                evidence={"pid": pid, "name": actual_name},
            )

        try:
            process.terminate()
            process.wait(timeout=5)
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status="executed",
                message="Process terminated after policy and identity verification",
                evidence={"pid": pid, "name": actual_name, "create_time": actual_created},
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as exc:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="terminate_process",
                status="failed",
                message=str(exc),
                evidence={"pid": pid, "name": actual_name},
            )

    def quarantine_file(self, alert: Alert) -> ResponseResult:
        file_path = str(alert.event.file.get("path") or alert.event.process.get("executable") or "")
        if not file_path:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="quarantine_file",
                status="blocked",
                message="No file path was present in the alert",
            )

        allowed, reason = self.policy.may_quarantine(file_path)
        if not allowed:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="quarantine_file",
                status=self._policy_status(reason),
                message=reason,
                evidence={"path": file_path},
            )

        try:
            source = Path(file_path).expanduser().resolve(strict=True)
            allowed, reason = self.policy.may_quarantine(str(source))
            if not allowed:
                return ResponseResult(
                    alert_id=alert.alert_id,
                    action="quarantine_file",
                    status=self._policy_status(reason),
                    message=reason,
                    evidence={"path": str(source)},
                )

            sha256 = self.scanner.hash_file(source)
            quarantine = Path(self.config.quarantine_directory).expanduser().resolve()
            quarantine.mkdir(parents=True, exist_ok=True)
            destination = quarantine / f"{sha256}.{alert.alert_id}.quarantine"
            shutil.move(str(source), destination)
            metadata = destination.with_suffix(".json")
            metadata.write_text(
                json.dumps(
                    {
                        "original_path": str(source),
                        "quarantined_path": str(destination),
                        "sha256": sha256,
                        "alert_id": alert.alert_id,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            if os.name != "nt":
                destination.chmod(0o600)
                metadata.chmod(0o600)
            return ResponseResult(
                alert_id=alert.alert_id,
                action="quarantine_file",
                status="executed",
                message="File moved to the configured quarantine directory",
                evidence={
                    "original_path": str(source),
                    "destination": str(destination),
                    "sha256": sha256,
                },
            )
        except (OSError, ValueError) as exc:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="quarantine_file",
                status="failed",
                message=str(exc),
                evidence={"path": file_path},
            )

    def isolate_host(self, alert: Alert) -> ResponseResult:
        return ResponseResult(
            alert_id=alert.alert_id,
            action="isolate_host",
            status="planned",
            message=(
                "Host isolation requires an approved operating-system plugin. "
                "The core framework records the plan but does not modify firewall rules."
            ),
            evidence={"host": alert.event.host},
        )

    def block_indicator(self, alert: Alert) -> ResponseResult:
        indicator = alert.event.network.get("remote_ip") or alert.event.file.get("sha256")
        if not indicator:
            return ResponseResult(
                alert_id=alert.alert_id,
                action="block_indicator",
                status="blocked",
                message="No network or file indicator was present in the alert",
            )
        return ResponseResult(
            alert_id=alert.alert_id,
            action="block_indicator",
            status="planned",
            message="Indicator block request recorded for external enforcement",
            evidence={"indicator": indicator},
        )
