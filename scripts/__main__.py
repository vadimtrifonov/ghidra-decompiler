import argparse
import json
import sys
from pathlib import Path

from . import trees
from .identity import identify
from .worker import launch


def parser():
    root = argparse.ArgumentParser(
        description="Decompilation trees of x64 Windows executables and DLLs; JSON on stdout."
    )
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("locate", "Report the state of a file's tree; never builds"),
        ("prepare", "Start building a file's tree in the background and return at once"),
    ):
        commands.add_parser(name, help=help_text).add_argument(
            "file", type=Path, help="x64 Windows executable or DLL"
        )
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        identity = identify(args.file)
        root = trees.root()
        report = launch(root, identity) if args.command == "prepare" else trees.state(root, identity)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
