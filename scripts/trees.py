"""Where trees are kept and what state a file's tree is in."""

import json
import os
from pathlib import Path

from .windows import lock_is_held

ROOT_VARIABLE = "GHIDRA_DECOMPILER_TREES"
STAGING_SUFFIX = ".preparing"


def root():
    value = os.environ.get(ROOT_VARIABLE)
    if not value:
        raise ValueError(
            f"{ROOT_VARIABLE} is not set. Ask the user for a folder to keep decompilation trees in, "
            f"then run: mise set --global {ROOT_VARIABLE}=<folder>"
        )
    return Path(value)


def lock_path(root, identity):
    return root / f"{identity.key}.lock"


def _folder(root, identity, suffix=""):
    matches = sorted(path for path in root.glob(f"*-{identity.key}{suffix}") if path.is_dir())
    return matches[0] if matches else None


def finished(root, identity):
    return _folder(root, identity)


def staging(root, identity):
    return _folder(root, identity, STAGING_SUFFIX)


def run_record(folder):
    """Read what the worker recorded about its run; empty when there is no readable record."""
    try:
        return json.loads((folder / "prepare.json").read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}


def export_record(folder):
    """Read the export script's last report, or None when it has not reported."""
    try:
        word, done, total, failed, *rest = (folder / "export.state").read_text(encoding="utf-8").split()
        return {
            "complete": word == "complete",
            "done": int(done),
            "total": int(total),
            "failed": int(failed),
            "ghidra": rest[0] if rest else None,
        }
    except OSError, ValueError:
        return None


def state(root, identity):
    # The lock is read first: a run renames its folder before it releases the lock.
    running = lock_is_held(lock_path(root, identity))
    if tree := finished(root, identity):
        return {"status": "ready", "tree": str(tree)}
    folder = staging(root, identity)
    record = run_record(folder) if folder else {}
    if running:
        report = {"status": "preparing", "stage": record.get("stage", "analysis")}
        for key in ("started", "pid"):
            if key in record:
                report[key] = record[key]
        if report["stage"] == "export" and (export := export_record(folder)):
            report |= {"functions_done": export["done"], "functions_total": export["total"]}
    elif not folder:
        return {"status": "absent"}
    elif "error" in record:
        report = {"status": "failed", "error": record["error"]}
    else:
        report = {"status": "interrupted"}
    if folder:
        report["log"] = str(folder / "prepare.log")
    return report
