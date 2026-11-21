---
name: ghidra-decompiler
description: Decompile x64 Windows executables and DLLs to C with Ghidra. The first build of a file runs in the background and can take over an hour.
---

# Ghidra Decompiler

Use this skill directory as the working directory.
Commands print JSON to stdout.

## Setup

```powershell
mise trust mise.toml
```

All trees are kept in one folder, named by `GHIDRA_DECOMPILER_TREES`.
Ask the user for the folder once and save it for this machine:

```powershell
mise set --global GHIDRA_DECOMPILER_TREES="D:\Path\To\Trees"
```

## Locate a tree

```powershell
mise run decompiler -- locate "C:\Path\To\image.exe"
```

| `status` | Meaning | Other fields |
|---|---|---|
| `ready` | The tree is complete | `tree` |
| `preparing` | A run is building the tree | `stage` (`analysis`, then `export`), `started`, `pid`, `log`; in the `export` stage also `functions_done` and `functions_total` |
| `failed` | The last run stopped with an error | `error`, `log` |
| `interrupted` | The last run ended without finishing and without recording an error | `log` |
| `absent` | No run has been started | |

The tree's folder is `<file name>-<file version>-<first 12 hex digits of the file's SHA-256>`.
Only the last part decides which tree belongs to a file, so a file changed by an update is `absent`.

## Prepare a tree

```powershell
mise run decompiler -- prepare "C:\Path\To\image.exe"
```

`prepare` starts a run in the background and returns at once with the report that `locate` gives.
It starts nothing when the tree is `ready` or a run is `preparing`.
After `failed` or `interrupted` it deletes what the earlier run left, including its log, and starts over.

`prepare` stops with an error when the file's code looks encrypted or compressed; executables wrapped by Steam DRM are a common case.
The tree then belongs to the unpacked copy, and `locate` reports the wrapped file as `absent`.

A run continues after the command, the agent, and its terminal have ended.
To stop a run, end the process `pid`; Ghidra ends with it.

A run renames its folder, the one that holds `log`, when it finishes.
A shell with that folder as its working directory, or a program with one of its files open, blocks the rename; the run waits ten minutes and then fails.

| File | Functions | Analysis | Export | Memory at peak | Tree on disk |
|---|---|---|---|---|---|
| A game executable, 102 MB | 202,742 | 45 min | 41 min | 15 GB in analysis, 12 GB in export | 2.6 GB |
| A system DLL, 0.6 MB | 1,604 | 30 s | 25 s | not measured | 21 MB |

Measured on a Ryzen 7 9800X3D with 64 GB of memory.
Analysis used 1.3 processor cores on average, and the export uses one.

## The tree

```text
<tree>\
├── functions\14196\141963f20.c
├── index.tsv
├── vtables.tsv
├── tree.json
├── prepare.log
└── ghidra\
```

Addresses are hexadecimal VAs at the file's preferred image base, without `0x`.

`functions` holds one file per function that Ghidra found, named after the function's entry address.
The subfolder is that address without its last four digits.

```c
// function 141660570  FUN_141660570
// vtable 144c8e540 ChargenMenu slot 0

void FUN_141660570(longlong param_1)
```

A `// vtable` line gives a vtable's address, its class, and the zero-based slot that points to the function.
A class has one vtable for each base class with virtual functions, so several functions can have the same class and slot; the vtable's address tells them apart.
A function that more than four slots point to has the line `// referenced by <N> vtable slots, listed in vtables.tsv` instead.

| File | Columns | Contents |
|---|---|---|
| `index.tsv` | `address`, `name`, `status` | Every function in address order; `status` is `ok` or `failed` |
| `vtables.tsv` | `vtable`, `class`, `slot`, `function` | Every slot of every vtable that Ghidra found through MSVC RTTI |
| `tree.json` | | `source`, `version`, `sha256`, `ghidra`, `functions`, `failed` |

A slot can point to an address that has no function file.

`ghidra` is the analyzed Ghidra project `project.gpr`.

## Reading the C

Ghidra names imports, exports, and library functions that it recognizes: under 1% of the functions of the game executable above.
A function without such a name is `FUN_<address>`; `FUN_141963f20` is `functions\14196\141963f20.c`.
`thunk_FUN_<address>` is a function that only jumps to `FUN_<address>`; its own address is in `index.tsv`, and several thunks can have the same name.
`Unwind@<address>` and `Catch_All@<address>` are the exception cleanup and catch code of other functions; they are 0.1% of the functions of the game executable above and 48% of another's.

`DAT_<address>` and `PTR_<name>_<address>` are data at that address; the tree does not hold what is there.
`PTR_vftable_<address>` is a stored pointer to a vtable, such as the start of an object, and the name leaves the class out.
The address that the file stores there is in `vtables.tsv`.
A read of read-only data shows as the value instead; a float that the decompiler did not recognize shows as its bits, such as `0x3f800000` for 1.0.

Parameter lists and return types are the decompiler's guesses.
A call can show an argument that the function does not take, lack some or all of those it passes, or drop a value returned in a vector register.
A function that ends in a jump to another function can hold that function's C as its own, without the `thunk_` name; its disassembly shows the jump.
A condition shown as `if (true)` or `if (false)` is one that the decompiler judged constant, and the side not taken is code that it judged unreachable.
The judgment is wrong where the decompiler lost track of what a call changes.

An address has no function file when it lies inside a function or in code that Ghidra did not make a function.
The function that holds an address is the nearest entry at or below it in `index.tsv`; in the game executable above that fails for code in 17 of the 202,742 functions.
The tree does not record where a function ends, so it cannot show that an address is in no function; disassemble the address to check.
The file of a function that Ghidra could not decompile holds `// decompile failed:` and the reason in place of the C; disassemble it too.

## Searching

Search `functions` with `rg`.
Over the 202,742 files of the game executable above, `rg` takes a few seconds and a recursive `Select-String` took 10 minutes.

A text search for a function's name finds the functions that call it.
It also finds their thunks, because a thunk's file holds the C of the function it jumps to.
It misses a call that the decompiler left out: the caller failed to decompile, or its file has a `WARNING` about a jump table.
