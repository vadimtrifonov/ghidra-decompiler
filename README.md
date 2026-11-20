# Ghidra Decompiler

Ghidra Decompiler is an agent skill for reading compiled x64 Windows executables and DLLs as C.
It runs [Ghidra](https://github.com/NationalSecurityAgency/ghidra) once on a file, in the background, and keeps the decompiled C of every function as a text file.

```c
// function 140689d00  FUN_140689d00
// vtable 144b352c0 MovementControllerComponentData slot 12

undefined8 FUN_140689d00(longlong param_1,undefined8 param_2)

{
  if (*(longlong *)(param_1 + 0x78) != 0) {
    FUN_140689d30(param_2,*(longlong *)(param_1 + 0x78) + 0x38);
    return 1;
  }
  return 0;
}
```

A file is named after its function's address.
Ghidra names what it can identify: imports, library functions, and the classes of virtual functions.
Other functions and data are named by their address, and fields are offsets.

## Install

The skill runs on Windows and needs [mise](https://mise.jdx.dev/), which installs the Ghidra, Java, and Python versions that the skill pins.
Install it with [skills](https://github.com/vercel-labs/skills):

```powershell
npx skills add vadimtrifonov/ghidra-decompiler
```

The agent builds the files for an executable when it first needs them, and asks for a folder to keep them in.

## Limits

The C is Ghidra's reconstruction: types are guesses, and a few functions do not decompile.
It does not show instructions or bytes, so hooks and patches still need a disassembler such as [Byte Inspector](https://github.com/vadimtrifonov/byte-inspector).

The first build of a file is slow.
A 102 MB game executable takes about 100 minutes, up to 15 GB of memory, and 2.6 GB of disk; a small DLL takes about a minute.
Each version of a file needs its own build.
