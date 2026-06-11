from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


TOOLING_SOURCE = Path(__file__).with_name("tooling.py").read_text(encoding="utf-8")


def _write_runtime_files(tmp_path: Path) -> None:
    (tmp_path / "tooling.py").write_text(TOOLING_SOURCE, encoding="utf-8")

    (tmp_path / "config_loader.py").write_text(
        """
from types import SimpleNamespace


def load_config():
    return SimpleNamespace(
        valid_domains={"example.com"},
        tools={"nmap_scan": SimpleNamespace(allowed_modes=("safe", "passive"))},
        logging=SimpleNamespace(run_dir="."),
    )
""".strip()
        + "\n",
        encoding="utf-8",
    )

    (tmp_path / "validation.py").write_text(
        """
class ValidationError(Exception):
    pass


def compose(*validators):
    def inner(value):
        for validator in validators:
            validator(value)

    return inner


def log_validation_failures(log_dir):
    def decorator(fn):
        return fn

    return decorator


def one_of(*allowed):
    def validator(value):
        if value not in allowed:
            raise ValidationError(f"must be one of: {', '.join(allowed)}")

    return validator


def require_non_empty(value):
    if not str(value).strip():
        raise ValidationError("must be non-empty")


def forbid_url_or_path(value):
    if "://" in value or "/" in value:
        raise ValidationError("must be domain-like")


def validate_inputs(**validators):
    def decorator(fn):
        def wrapped(*args, **kwargs):
            arg_names = fn.__code__.co_varnames[: fn.__code__.co_argcount]
            merged = dict(zip(arg_names, args))
            merged.update(kwargs)
            for key, validator in validators.items():
                if key in merged:
                    validator(merged[key])
            return fn(*args, **kwargs)

        return wrapped

    return decorator
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _load_tooling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _write_runtime_files(tmp_path)
    monkeypatch.chdir(tmp_path)
    sys.path.insert(0, str(tmp_path))

    if "tooling" in sys.modules:
        del sys.modules["tooling"]

    return importlib.import_module("tooling")


def _unload_tooling(tmp_path: Path) -> None:
    if str(tmp_path) in sys.path:
        sys.path.remove(str(tmp_path))
    if "tooling" in sys.modules:
        del sys.modules["tooling"]


def test_nmap_scan_normalizes_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tooling = _load_tooling(tmp_path, monkeypatch)

    try:
        result = tooling.nmap_scan(" Example.com ", "safe", execute=False)
        assert result["target"] == "example.com"
        assert result["status"] == "accepted_dry_run"
        assert result["duration_ms"] >= 0
    finally:
        _unload_tooling(tmp_path)


def test_nmap_scan_handles_missing_nmap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tooling = _load_tooling(tmp_path, monkeypatch)

    try:
        def fake_run(*args, **kwargs):
            raise FileNotFoundError()

        monkeypatch.setattr(tooling.subprocess, "run", fake_run)

        with pytest.raises(tooling.ValidationError, match="nmap is not installed"):
            tooling.nmap_scan("example.com", "safe", execute=True)
    finally:
        _unload_tooling(tmp_path)


def test_nmap_scan_handles_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tooling = _load_tooling(tmp_path, monkeypatch)

    try:
        def fake_run(*args, **kwargs):
            raise tooling.subprocess.TimeoutExpired(cmd="nmap", timeout=kwargs["timeout"])

        monkeypatch.setattr(tooling.subprocess, "run", fake_run)

        with pytest.raises(Exception, match="exceeded timeout of 5s"):
            tooling.nmap_scan("example.com", "safe", execute=True, timeout_seconds=5)
    finally:
        _unload_tooling(tmp_path)


def test_nmap_scan_records_duration_when_executed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tooling = _load_tooling(tmp_path, monkeypatch)

    try:
        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(tooling.subprocess, "run", fake_run)

        result = tooling.nmap_scan("example.com", "safe", execute=True)

        assert result["status"] == "completed"
        assert result["duration_ms"] >= 0
        assert result["returncode"] == 0
    finally:
        _unload_tooling(tmp_path)
