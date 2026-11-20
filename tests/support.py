import ctypes
import json
import os
import random
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

from scripts.trees import ROOT_VARIABLE

SKILL = Path(__file__).resolve().parents[1]
SYSTEM = Path(os.environ["SystemRoot"])

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
_SYNCHRONIZE = 0x00100000
_WAIT_TIMEOUT = 0x102

# Stands in for Ghidra's launcher: the import does nothing, the export writes one file and one report.
_STUB_LAUNCHER = r"""@echo off
:next
if "%~1"=="" exit /b 0
if "%~1"=="-postScript" goto export
shift
goto next
:export
mkdir "%~3\functions\14000"
>"%~3\functions\14000\%STUB_EXPORT%.c" echo // function 140001000  FUN_140001000
if "%STUB_EXPORT%"=="complete" (set "REPORT=complete 1 1 0 stub") else (set "REPORT=running 1 10 0")
>"%~3\export.state" echo %REPORT%
exit /b 0
"""


# Takes the lock, hands it to a child the way the worker hands it to Ghidra, and prints the child's ID.
_LOCK_HOLDER = """
import subprocess, sys, time
from scripts.windows import hold_lock
lock = hold_lock(sys.argv[1])
heir = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"],
    stdout=subprocess.DEVNULL,
    startupinfo=subprocess.STARTUPINFO(lpAttributeList={"handle_list": [lock]}),
)
print(heir.pid, flush=True)
time.sleep(60)
"""


def lock_holder_and_heir(lock):
    """Start a process that holds the lock and a child that inherited it; return the first and the child's ID."""
    holder = subprocess.Popen(
        [sys.executable, "-B", "-c", _LOCK_HOLDER, str(lock)], cwd=SKILL, stdout=subprocess.PIPE, text=True
    )
    heir = int(holder.stdout.readline())
    holder.stdout.close()
    return holder, heir


def _image(data):
    """Return a PE file's image base and the virtual size, RVA, raw size, file offset, and flags of its sections."""
    header = struct.unpack_from("<I", data, 0x3C)[0]
    count, optional_size = (
        struct.unpack_from("<H", data, header + 6)[0],
        struct.unpack_from("<H", data, header + 20)[0],
    )
    table = header + 24 + optional_size
    sections = [struct.unpack_from("<IIII12xI", data, table + 40 * i + 8) for i in range(count)]
    return struct.unpack_from("<Q", data, header + 48)[0], sections


def with_encrypted_code(source, target):
    """Copy a PE file with random bytes in place of its largest code section, as Steam's DRM can leave one."""
    data = bytearray(Path(source).read_bytes())
    size, offset = max(
        (raw_size, offset) for _, _, raw_size, offset, flags in _image(data)[1] if flags & 0x20000000
    )
    data[offset : offset + size] = random.Random(0).randbytes(size)
    target.write_bytes(data)
    return target, size


def pointer_reader(path):
    """Return a function that reads the 64-bit value at a VA of a PE file, or None outside its section data."""
    data = Path(path).read_bytes()
    base, sections = _image(data)

    def read(va):
        for virtual_size, rva, raw_size, offset, _ in sections:
            if 0 <= va - base - rva <= min(virtual_size, raw_size) - 8:
                return struct.unpack_from("<Q", data, offset + va - base - rva)[0]

    return read


def stub_ghidra(folder):
    (folder / "support").mkdir(parents=True)
    (folder / "support" / "analyzeHeadless.bat").write_text(_STUB_LAUNCHER, encoding="ascii")
    return folder


def decompiler(command, file, root, **environment):
    """Run one command of the tool; return its exit code, its JSON report or None, and its diagnostics."""
    variables = os.environ | environment
    variables.pop(ROOT_VARIABLE, None)
    if root:
        variables[ROOT_VARIABLE] = str(root)
    done = subprocess.run(
        [sys.executable, "-B", "-m", "scripts", command, str(file)],
        cwd=SKILL,
        env=variables,
        capture_output=True,
        text=True,
    )
    return done.returncode, json.loads(done.stdout) if done.stdout else None, done.stderr


def wait_for(condition, seconds, what):
    deadline = time.monotonic() + seconds
    while not (value := condition()):
        if time.monotonic() > deadline:
            raise TimeoutError(f"no {what} within {seconds} seconds")
        time.sleep(0.2)
    return value


def descendants(pid):
    """Map the process IDs below pid to their image names."""
    listing = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    processes = json.loads(listing.stdout)
    found, frontier = {}, {pid}
    while frontier:
        below = {row["ProcessId"]: row["Name"] for row in processes if row["ParentProcessId"] in frontier}
        frontier = below.keys() - found.keys()
        found |= below
    return found


def watch(pid):
    """Return a handle that still names this process after its ID has been reused, or None if it has ended."""
    return _kernel32.OpenProcess(_SYNCHRONIZE, False, pid)


def is_running(handle):
    return _kernel32.WaitForSingleObject(handle, 0) == _WAIT_TIMEOUT
