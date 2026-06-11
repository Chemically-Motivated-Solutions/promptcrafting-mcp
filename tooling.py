from __future__ import annotations

import shlex
import subprocess
import time
from typing import Any

from config_loader import load_config
from validation import (
    ValidationError,
    compose,
    log_validation_failures,
    one_of,
    require_non_empty,
    forbid_url_or_path,
    validate_inputs,
)


CONFIG = load_config()


def normalize_target(value: str) -> str:
    """
    Normalize a target string by trimming surrounding whitespace and converting all characters to lowercase.
    
    Parameters:
        value (str): The target string to normalize.
    
    Returns:
        normalized (str): The input string with leading and trailing whitespace removed and converted to lowercase.
    """
    return value.strip().lower()


def require_allowed_domain(allowed: set[str] | frozenset[str]):
    """
    Builds a validator that ensures a target is one of the specified allowed values after normalization.
    
    Parameters:
        allowed (set[str] | frozenset[str]): Collection of allowed target strings; each entry will be normalized using normalize_target before comparison.
    
    Returns:
        validator (Callable[[str], None]): A function that validates a value and raises ValidationError("must be one of: ...") if the normalized value is not in the allowed set.
    """
    normalized_allowed = frozenset(normalize_target(x) for x in allowed)
    allowed_list = ", ".join(sorted(normalized_allowed))

    def validator(value: str) -> None:
        """
        Validate that the normalized input is one of the preconfigured allowed targets.
        
        Parameters:
            value (str): The target string to validate.
        
        Raises:
            ValidationError: If the normalized `value` is not in the allowed set; message will be "must be one of: <allowed_list>".
        """
        if normalize_target(value) not in normalized_allowed:
            raise ValidationError(f"must be one of: {allowed_list}")

    return validator


validate_target = compose(
    require_non_empty,
    forbid_url_or_path,
    require_allowed_domain(CONFIG.valid_domains),
)

allowed_modes = (
    CONFIG.tools.get("nmap_scan").allowed_modes
    if "nmap_scan" in CONFIG.tools
    else ("safe",)
)


def _build_nmap_command(target: str, mode: str) -> list[str]:
    """
    Builds the nmap command argument list for the given target and scan mode.
    
    Parameters:
        target (str): Host or domain to scan; the value will be normalized (trimmed and lowercased).
    	mode (str): Scan mode; "safe" for a top-ports scan, "passive" for a host-discovery scan.
    
    Returns:
    	command_args (list[str]): The argv-style list suitable for subprocess (e.g. ["nmap", ... , target]).
    
    Raises:
    	ValidationError: If `mode` is not one of the supported values.
    """
    normalized_target = normalize_target(target)

    if mode == "safe":
        return ["nmap", "-Pn", "--top-ports", "20", normalized_target]

    if mode == "passive":
        return ["nmap", "-sn", normalized_target]

    raise ValidationError(f"unsupported mode: {mode}")


@log_validation_failures(log_dir=CONFIG.logging.run_dir)
@validate_inputs(
    target=validate_target,
    mode=one_of(*allowed_modes),
)
def nmap_scan(
    target: str,
    mode: str = "safe",
    execute: bool = False,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """
    Prepare and optionally execute an nmap scan for the given target.
    
    Parameters:
        target (str): Hostname or domain to scan; it will be normalized (trimmed and lowercased).
        mode (str): Scan mode; expected values include "safe" (top ports scan) and "passive" (host discovery).
        execute (bool): If False, perform a dry run and return the prepared command without running nmap.
        timeout_seconds (int): Maximum time in seconds to allow nmap to run before timing out.
    
    Returns:
        dict: Result summary containing:
            - tool (str): "nmap_scan"
            - target (str): normalized target
            - mode (str): requested mode
            - command (str): shell-escaped command string
            - execute (bool)
            - timeout_seconds (int)
            - status (str): "accepted_dry_run" for dry runs or "completed" after execution
            - duration_ms (float): elapsed time in milliseconds (rounded to 3 decimals)
            - returncode (int, optional): subprocess return code (present when executed)
            - stdout (str, optional): captured stdout (present when executed)
            - stderr (str, optional): captured stderr (present when executed)
    
    Raises:
        ValidationError: If the mode is unsupported, if nmap is not available in PATH, or if execution exceeds the timeout.
    """
    command = _build_nmap_command(target, mode)
    started = time.perf_counter()

    result: dict[str, Any] = {
        "tool": "nmap_scan",
        "target": normalize_target(target),
        "mode": mode,
        "command": shlex.join(command),
        "execute": execute,
        "timeout_seconds": timeout_seconds,
    }

    if not execute:
        result["status"] = "accepted_dry_run"
        result["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return result

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise ValidationError("nmap is not installed or not available in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValidationError(f"nmap execution exceeded timeout of {timeout_seconds}s") from exc

    result["status"] = "completed"
    result["returncode"] = completed.returncode
    result["stdout"] = completed.stdout
    result["stderr"] = completed.stderr
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return result
