"""Building a tree: the launch from `prepare`, and the detached worker that runs Ghidra and publishes."""

import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from . import trees, windows
from .identity import encrypted_code, identify

SKILL = Path(__file__).resolve().parents[1]
GHIDRA_SCRIPTS = Path(__file__).resolve().parent / "ghidra"


def launch(root, identity):
    """Start a worker unless a tree exists or a run is alive; return the state once the worker has recorded itself."""
    current = trees.state(root, identity)
    if current["status"] in ("ready", "preparing"):
        return current
    if reason := encrypted_code(identity.source):
        raise ValueError(f"{reason}; prepare an unpacked copy of the file")
    root.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-B", "-m", "scripts.worker", str(identity.source)]
    flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    silent = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    try:
        worker = subprocess.Popen(
            command, cwd=SKILL, creationflags=flags | subprocess.CREATE_BREAKAWAY_FROM_JOB, **silent
        )
    except PermissionError:  # the caller's job does not let processes leave it
        worker = subprocess.Popen(command, cwd=SKILL, creationflags=flags, **silent)
    while True:
        ended = worker.poll() is not None
        current = trees.state(root, identity)
        if ended or current["status"] == "ready" or current.get("pid") == worker.pid:
            break
        time.sleep(0.1)
    if current["status"] == "absent":
        raise RuntimeError("the worker ended before it recorded a run")
    return current


def _retry(action, seconds=600):
    """Repeat a file operation while another process briefly has one of the files open."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            return action()
        except PermissionError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def _remove(path):
    _retry(lambda: shutil.rmtree(path) if path.is_dir() else path.unlink(missing_ok=True))


def _write_record(folder, record):
    (folder / "prepare.json").write_text(json.dumps(record), encoding="utf-8")


def _ghidra(stage, arguments, folder, log, lock):
    launcher = Path(os.environ["GHIDRA_INSTALL_DIR"]) / "support" / "analyzeHeadless.bat"
    quoted = " ".join(f'"{item}"' for item in (launcher, folder / "ghidra", "project", *arguments))
    code = subprocess.run(
        f'cmd.exe /d /s /c "{quoted}"',
        stdin=subprocess.DEVNULL,  # the launcher pauses for a key after a failure
        stdout=log,
        stderr=subprocess.STDOUT,
        env=os.environ
        | {"XDG_CONFIG_HOME": str(folder / "settings"), "XDG_CACHE_HOME": str(folder / "cache")},
        creationflags=subprocess.CREATE_NO_WINDOW,
        startupinfo=subprocess.STARTUPINFO(lpAttributeList={"handle_list": [lock]}),
    ).returncode
    if code:
        raise RuntimeError(f"Ghidra exited with code {code} during {stage}")


def _build(identity, folder, record, lock):
    (folder / "ghidra").mkdir()
    with (folder / "prepare.log").open("ab") as log:
        script = ["-noanalysis", "-scriptPath", GHIDRA_SCRIPTS, "-postScript"]
        # Ghidra chooses its analyzers when it opens a program, so the compiler is set in a run before the analysis.
        recognize = ["-import", identity.source, *script, "RecognizeCompiler.java", folder]
        _ghidra("analysis", recognize, folder, log, lock)
        # Ghidra exits with 0 when a script fails, so only a script's own last report proves that it finished.
        if not (folder / "compiler.txt").exists():
            raise RuntimeError("Ghidra produced no compiler report")
        _ghidra("analysis", ["-process", identity.source.name], folder, log, lock)
        _write_record(folder, record | {"stage": "export"})
        _ghidra("export", ["-process", "-readOnly", *script, "ExportTree.java", folder], folder, log, lock)
    report = trees.export_record(folder)
    if not report:
        raise RuntimeError("Ghidra produced no export")
    if not report["complete"]:
        raise RuntimeError(f"the export stopped after {report['done']} of {report['total']} functions")
    manifest = {
        "source": str(identity.source),
        "version": identity.version,
        "sha256": identity.sha256,
        "ghidra": report["ghidra"],
        "functions": report["done"],
        "failed": report["failed"],
    }
    (folder / "tree.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    for name in ("settings", "cache", "compiler.txt", "export.state", "prepare.json"):
        _remove(folder / name)
    _retry(lambda: folder.rename(folder.with_name(identity.name)))


def main(source):
    identity = identify(source)
    root = trees.root()
    lock = windows.hold_lock(trees.lock_path(root, identity))
    if lock is None or trees.finished(root, identity):
        return 0
    windows.end_children_with_this_process()
    folder = root / (identity.name + trees.STAGING_SUFFIX)
    record = {
        "source": str(identity.source),
        "started": datetime.now().isoformat(timespec="seconds"),
        "pid": os.getpid(),
        "stage": "analysis",
    }
    try:
        # Whatever an earlier run left is removed here, under the lock, so no live run can lose its files.
        while (leftover := trees.staging(root, identity)) and leftover != folder:
            _remove(leftover)
        folder.mkdir(exist_ok=True)
        _write_record(folder, record)
        for child in folder.iterdir():
            if child.name != "prepare.json":
                _remove(child)
        _build(identity, folder, record, lock)
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else f"{type(error).__name__}: {error}"
        with contextlib.suppress(OSError):
            _write_record(folder, record | {"error": message})
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
