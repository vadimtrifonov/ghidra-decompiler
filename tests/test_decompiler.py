import ctypes
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from collections import defaultdict
from ctypes import wintypes
from pathlib import Path

from support import (
    SYSTEM,
    decompiler,
    descendants,
    is_running,
    lock_holder_and_heir,
    pointer_reader,
    stub_ghidra,
    wait_for,
    watch,
    with_encrypted_code,
    without_dos_stub,
)

from scripts.identity import encrypted_code, identify, version_label
from scripts.trees import ROOT_VARIABLE, lock_path, state
from scripts.windows import hold_lock, lock_is_held


class DecompilerTests(unittest.TestCase):
    FILE = SYSTEM / "System32" / "whoami.exe"

    def setUp(self):
        # The space checks that paths survive Ghidra's batch launcher.
        temporary = tempfile.TemporaryDirectory(prefix="ghidra decompiler test ", ignore_cleanup_errors=True)
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.root = self.folder / "trees"
        self.root.mkdir()
        self.addCleanup(self.end_run)

    def state(self):
        return decompiler("locate", self.FILE, self.root)[1]

    def run_ended(self, seconds):
        return wait_for(
            lambda: (report := self.state())["status"] != "preparing" and report, seconds, "end of the run"
        )

    def end_run(self):
        report = self.state()
        if report["status"] == "preparing":
            os.kill(report["pid"], signal.SIGTERM)
            self.run_ended(60)


class OfflineTests(DecompilerTests):
    def test_version_label_is_the_leading_dotted_number(self):
        for text, numeric, expected in (
            ("1.16.244.0", "1.16.244.0", "1.16.244.0"),
            ("1.4.15", "1.4.15.0", "1.4.15"),
            ("10.0.26100.1 (WinBuild.160101.0800)", "10.0.26100.1", "10.0.26100.1"),
            ("2,2,0,0", "2.2.0.0", "2.2.0.0"),
            ("1, 0, 0, 1", "1.0.0.1", "1.0.0.1"),
            ("beta 3", "3.0.0.0", "3.0.0.0"),
            (None, None, None),
        ):
            with self.subTest(text=text):
                self.assertEqual(version_label(text, numeric), expected)

    def test_folder_name_is_file_name_version_and_hash_of_the_contents(self):
        identity = identify(self.FILE)
        self.assertRegex(identity.name, r"^whoami\.exe-\d+(\.\d+)+-[0-9a-f]{12}$")
        self.assertEqual(identity.sha256, hashlib.sha256(self.FILE.read_bytes()).hexdigest())
        copy = identify(shutil.copy(self.FILE, self.folder / "another name.exe"))
        self.assertEqual(copy.key, identity.key)
        self.assertEqual(copy.name, identity.name.replace("whoami.exe", "another name.exe"))

    def test_only_x64_pe_files_are_accepted(self):
        for path in (Path(__file__), SYSTEM / "SysWOW64" / "whoami.exe"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                identify(path)

    def test_prepare_refuses_a_file_whose_code_is_encrypted(self):
        # The entropy of a code section is taken from all of a small one and from samples of a large one.
        for source, sampled in ((self.FILE, False), (SYSTEM / "System32" / "msvcp140.dll", True)):
            with self.subTest(source=source.name):
                self.assertIsNone(encrypted_code(source))
                wrapped, size = with_encrypted_code(source, self.folder / source.name)
                self.assertEqual(size > 64 * 4096, sampled)
                code, report, diagnostics = decompiler("prepare", wrapped, self.root)
                self.assertEqual((code, report), (1, None))
                self.assertIn("looks encrypted or compressed", diagnostics)
                self.assertEqual(list(self.root.iterdir()), [])
                self.assertEqual(decompiler("locate", wrapped, self.root)[1], {"status": "absent"})

    def test_commands_stop_when_the_tree_folder_is_not_set(self):
        for command in ("locate", "prepare"):
            with self.subTest(command=command):
                code, report, diagnostics = decompiler(command, self.FILE, None)
                self.assertEqual((code, report), (1, None))
                self.assertIn(ROOT_VARIABLE, diagnostics)

    def test_state_follows_the_folders_and_the_lock(self):
        identity = identify(self.FILE)
        self.assertEqual(state(self.root, identity), {"status": "absent"})

        folder = self.root / f"{identity.name}.preparing"
        folder.mkdir()
        log = str(folder / "prepare.log")
        self.assertEqual(state(self.root, identity), {"status": "interrupted", "log": log})

        record = {"started": "2026-01-01T00:00:00", "pid": 1, "stage": "export"}
        (folder / "prepare.json").write_text(json.dumps(record | {"error": "boom"}), encoding="utf-8")
        self.assertEqual(state(self.root, identity), {"status": "failed", "error": "boom", "log": log})

        lock = hold_lock(lock_path(self.root, identity))
        self.assertIsNone(hold_lock(lock_path(self.root, identity)))
        (folder / "prepare.json").write_text(json.dumps(record), encoding="utf-8")
        (folder / "export.state").write_text("running 2000 5000 3\n", encoding="utf-8")
        self.assertEqual(
            state(self.root, identity),
            {"status": "preparing", "stage": "export", "started": record["started"], "pid": 1}
            | {"functions_done": 2000, "functions_total": 5000, "log": log},
        )

        # A tree made from a copy under another name is this file's tree too.
        tree = self.root / f"renamed.exe-{identity.key}"
        tree.mkdir()
        self.assertEqual(state(self.root, identity), {"status": "ready", "tree": str(tree)})

        ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(lock))
        self.assertFalse(lock_path(self.root, identity).exists())

    def test_lock_lasts_until_every_process_that_inherited_it_has_ended(self):
        lock = self.root / "run.lock"
        holder, heir = lock_holder_and_heir(lock)
        self.addCleanup(subprocess.run, ["taskkill", "/F", "/PID", str(heir)], capture_output=True)
        self.assertTrue(lock_is_held(lock))
        holder.kill()
        holder.wait()
        self.assertTrue(lock_is_held(lock))
        os.kill(heir, signal.SIGTERM)
        wait_for(lambda: not lock_is_held(lock), 5, "release of the lock")
        self.assertFalse(lock.exists())


class WorkerTests(DecompilerTests):
    def test_run_without_a_script_report_is_not_published_and_a_retry_starts_over(self):
        ghidra = stub_ghidra(self.folder / "ghidra stub")

        def prepare(reports):
            decompiler("prepare", self.FILE, self.root, GHIDRA_INSTALL_DIR=str(ghidra), STUB_REPORTS=reports)
            return self.run_ended(60)

        # The stub exits with 0, as Ghidra does when one of its scripts fails.
        report = prepare("none")
        self.assertEqual(report["status"], "failed", report)
        self.assertEqual(report["error"], "Ghidra produced no compiler report")
        self.assertFalse((Path(report["log"]).parent / "functions").exists())

        report = prepare("partial")
        self.assertEqual(report["status"], "failed", report)
        self.assertEqual(report["error"], "the export stopped after 1 of 10 functions")
        leftover = Path(report["log"]).parent
        self.assertTrue(Path(report["log"]).is_file())
        self.assertTrue((leftover / "functions" / "14000" / "partial.c").is_file())
        self.assertEqual([path.name for path in self.root.iterdir()], [leftover.name])

        report = prepare("complete")
        self.assertEqual(report["status"], "ready", report)
        tree = Path(report["tree"])
        self.assertEqual([path.name for path in self.root.iterdir()], [tree.name])
        self.assertEqual(
            sorted(path.name for path in tree.iterdir()), ["functions", "ghidra", "prepare.log", "tree.json"]
        )
        self.assertEqual([path.name for path in (tree / "functions" / "14000").iterdir()], ["complete.c"])
        manifest = json.loads((tree / "tree.json").read_text(encoding="utf-8"))
        identity = identify(self.FILE)
        self.assertEqual(
            manifest,
            {"source": str(identity.source), "version": identity.version, "sha256": identity.sha256}
            | {"ghidra": "stub", "functions": 1, "failed": 0},
        )


class GhidraTests(DecompilerTests):
    # A small C++ library: 1,604 functions, 93 vtables, some functions referenced by more than four slots.
    FILE = SYSTEM / "System32" / "msvcp140.dll"

    def test_tree_holds_every_function_and_agrees_with_its_tables(self):
        # Ghidra reads the compiler from the DOS stub, and without the compiler it finds no vtables by itself.
        self.FILE = without_dos_stub(self.FILE, self.folder / self.FILE.name)
        self.assertEqual(decompiler("prepare", self.FILE, self.root)[1]["status"], "preparing")
        report = self.run_ended(600)
        self.assertEqual(report["status"], "ready", report)
        tree = Path(report["tree"])
        self.assertEqual([path.name for path in self.root.iterdir()], [tree.name])
        self.assertEqual(
            sorted(path.name for path in tree.iterdir()),
            ["functions", "ghidra", "index.tsv", "prepare.log", "tree.json", "vtables.tsv"],
        )

        def table(name):
            return [line.split("\t") for line in (tree / name).read_text(encoding="utf-8").splitlines()[1:]]

        index = table("index.tsv")
        files = {path.stem: path for path in (tree / "functions").glob("*/*.c")}
        manifest = json.loads((tree / "tree.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["sha256"], hashlib.sha256(self.FILE.read_bytes()).hexdigest())
        self.assertEqual(manifest["functions"], len(index))
        self.assertEqual(manifest["failed"], sum(status == "failed" for *_, status in index))
        self.assertEqual(sorted(files), [address for address, *_ in index])
        # Ghidra's C arrives with CRLF line ends.
        for path in (tree / "index.tsv", tree / "vtables.tsv", tree / "tree.json", *files.values()):
            self.assertNotIn(b"\r", path.read_bytes(), path)

        slots, vtables = defaultdict(list), defaultdict(list)
        for vtable, owner, slot, function in table("vtables.tsv"):
            slots[function].append(f"// vtable {vtable} {owner} slot {slot}")
            vtables[vtable].append((int(slot), function))
        self.assertLessEqual(slots.keys(), files.keys())
        pointer = pointer_reader(self.FILE)
        for vtable, rows in vtables.items():
            cells = [f"{pointer(int(vtable, 16) + 8 * slot):x}" for slot in range(len(rows) + 1)]
            with self.subTest(vtable=vtable):
                self.assertEqual(rows, list(enumerate(cells[:-1])))
                # In this library no vtable is followed by a further function pointer, so one cut short shows here.
                self.assertNotIn(cells[-1], files)
        self.assertEqual({len(lines) > 4 for lines in slots.values()}, {True, False})
        for address, name, status in index:
            listed = slots.get(address, [])
            if len(listed) > 4:
                listed = [f"// referenced by {len(listed)} vtable slots, listed in vtables.tsv"]
            lines = files[address].read_text(encoding="utf-8").splitlines()
            head = [f"// function {address}  {name}", *listed]
            with self.subTest(address=address):
                self.assertEqual(files[address].parent.name, address[:-4])
                self.assertEqual(lines[: len(head)], head)
                self.assertEqual(lines[len(head)].startswith("// decompile failed"), status == "failed")

        self.assertEqual(decompiler("prepare", self.FILE, self.root)[1], report)

    def test_export_cut_short_is_not_published(self):
        worker = decompiler("prepare", self.FILE, self.root)[1]["pid"]
        wait_for(lambda: "functions_total" in self.state(), 600, "export")
        for pid, name in descendants(worker).items():
            if name == "java.exe":
                os.kill(pid, signal.SIGTERM)
        report = self.run_ended(60)
        self.assertEqual(report["status"], "failed", report)
        self.assertIn("during export", report["error"])
        leftover = Path(report["log"]).parent
        self.assertTrue(leftover.name.endswith(".preparing"))
        self.assertEqual([path.name for path in self.root.iterdir()], [leftover.name])

    def test_killed_worker_ends_ghidra_and_a_retry_starts_only_after(self):
        started = decompiler("prepare", self.FILE, self.root)[1]
        worker, log = started["pid"], Path(started["log"])
        # Output means Ghidra itself runs; the launcher's short-lived helpers before it print nothing.
        wait_for(lambda: log.is_file() and log.stat().st_size, 120, "Ghidra's first output")
        run = descendants(worker)
        self.assertIn("java.exe", run.values())
        watched = [handle for pid, name in run.items() if name != "conhost.exe" and (handle := watch(pid))]

        os.kill(worker, signal.SIGTERM)
        killed = time.monotonic()
        # A retry reports the killed run for as long as one of its processes holds the lock.
        while (retry := decompiler("prepare", self.FILE, self.root)[1]).get("pid") == worker:
            # Analysis of this file takes about 25 seconds, so only the worker's end explains Ghidra's.
            self.assertLess(time.monotonic() - killed, 10, "Ghidra outlived the killed worker")
        self.assertEqual(retry["status"], "preparing", retry)
        # Windows reports a process as ended a moment after it has closed its files and released the lock.
        wait_for(lambda: not any(map(is_running, watched)), 1, "end of the killed run's processes")
