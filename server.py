#!/usr/bin/env python3
"""Minimal MCP Python PenTest Server (v1).

Exposes exactly three tools with fixed command patterns:
- nmap_scan   -> nmap -F <target>
- curl_head   -> curl -I <target>
- whois_lookup-> whois <target>
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
from typing import TypedDict

from mcp.server.fastmcp import FastMCP


class ToolResult(TypedDict):
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
TIMEOUT_SECONDS = int(os.getenv("TOOL_TIMEOUT_SECONDS", "20"))
MAX_OUTPUT_CHARS = int(os.getenv("MAX_OUTPUT_CHARS", "20000"))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("pentest-mcp")

mcp = FastMCP("pentest-mcp-v1")

# Allows domains, IPv4, IPv6, hostnames, and optional URL-ish punctuation used by curl.
_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/?&=%#@+\-\[\]]{0,253}$")


def _invalid_target_result(command: str, reason: str) -> ToolResult:
    return {
        "ok": False,
        "command": command,
        "exit_code": 2,
        "stdout": "",
        "stderr": f"invalid target: {reason}",
        "truncated": False,
    }


def _validate_target(target: str) -> str | None:
    if target is None:
        return "target is required"
    candidate = target.strip()
    if not candidate:
        return "target cannot be empty"
    if len(candidate) > 254:
        return "target is too long"
    if " " in candidate or "\t" in candidate or "\n" in candidate:
        return "target cannot contain whitespace"
    if not _TARGET_PATTERN.match(candidate):
        return "target contains unsupported characters"
    return None


def _truncate(value: str) -> tuple[str, bool]:
    if len(value) <= MAX_OUTPUT_CHARS:
        return value, False
    return value[:MAX_OUTPUT_CHARS], True


def _run_tool(command: list[str], target: str) -> ToolResult:
    validation_error = _validate_target(target)
    cmd_str = " ".join(shlex.quote(part) for part in command)
    if validation_error:
        return _invalid_target_result(cmd_str, validation_error)

    redacted_cmd_str = re.sub(r"(://[^:]+:)[^@]+@", r"\1<redacted>@", cmd_str)
    logger.info("executing command=%s", redacted_cmd_str)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
        stdout, stdout_truncated = _truncate(completed.stdout)
        stderr, stderr_truncated = _truncate(completed.stderr)
        return {
            "ok": completed.returncode == 0,
            "command": cmd_str,
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": stdout_truncated or stderr_truncated,
        }
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "command": cmd_str,
            "exit_code": 127,
            "stdout": "",
            "stderr": f"binary not found: {exc.filename}",
            "truncated": False,
        }
    except subprocess.TimeoutExpired as exc:
        partial_stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        partial_stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        stdout, stdout_truncated = _truncate(partial_stdout)
        stderr, stderr_truncated = _truncate(partial_stderr)
        return {
            "ok": False,
            "command": cmd_str,
            "exit_code": 124,
            "stdout": stdout,
            "stderr": (stderr + "\n" if stderr else "")
            + f"process timed out after {TIMEOUT_SECONDS}s",
            "truncated": stdout_truncated or stderr_truncated,
        }
    except Exception as exc:  # defensive: do not crash the server on unexpected subprocess errors
        logger.exception("unexpected tool execution failure")
        return {
            "ok": False,
            "command": cmd_str,
            "exit_code": 1,
            "stdout": "",
            "stderr": f"unexpected execution error: {type(exc).__name__}: {exc}",
            "truncated": False,
        }


@mcp.tool(
    name="nmap_scan",
    description="Run fast port discovery with fixed pattern: nmap -F <target>",
)
def nmap_scan(target: str) -> ToolResult:
    return _run_tool(["nmap", "-F", target], target)


@mcp.tool(
    name="curl_head",
    description="Run HTTP header inspection with fixed pattern: curl -I <target>",
)
def curl_head(target: str) -> ToolResult:
    return _run_tool(["curl", "-I", target], target)


@mcp.tool(
    name="whois_lookup",
    description="Run domain lookup with fixed pattern: whois <target>",
)
def whois_lookup(target: str) -> ToolResult:
    return _run_tool(["whois", target], target)


if __name__ == "__main__":
    # Default stdio transport works with MCP Inspector / desktop MCP clients.
    mcp.run()
