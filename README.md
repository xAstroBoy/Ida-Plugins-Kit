# DumpToolkit

Dump **everything** from a binary into flat files for offline analysis. Two plugins, one for IDA Pro, one for Binary Ninja — plus CLI lookup tools that search the dumps instantly with zero truncation.

## Repository Structure

```
├── ida/
│   ├── DumpToolkit.py       # IDA Pro 9.x plugin — 25 dump types
│   └── ida_lookup.py        # CLI search tool for IDA dumps (22 commands)
├── binja/
│   ├── BinjaDumpToolkit.py  # Binary Ninja plugin — 19 dump types
│   └── binja_lookup.py      # CLI search tool for Binja dumps (24 commands)
├── IDA_API_DUMP_REFERENCE.md
└── README.md
```

---

## Feature Comparison

| Dump Category | IDA | Binja | Output File |
|---|:---:|:---:|---|
| Assembly | ✓ | ✓ | `ALL_ASSEMBLY.asm` |
| Decompiled (pseudocode) | ✓ | ✓ | `ALL_DECOMPILED.c` |
| Binary Overview | ✓ | ✓ | `ALL_OVERVIEW.txt` |
| Strings | ✓ | ✓ | `ALL_STRINGS.txt` |
| Names / Symbols | ✓ | ✓ | `ALL_NAMES.txt` |
| Imports | ✓ | ✓ | `ALL_IMPORTS.txt` |
| Exports | ✓ | ✓ | `ALL_EXPORTS.txt` |
| Segments | ✓ | ✓ | `ALL_SEGMENTS.txt` |
| Cross-References | ✓ | ✓ | `ALL_XREFS.txt` |
| Function Details | ✓ | ✓ | `ALL_FUNCTION_DETAILS.txt` / `ALL_FUNCTIONS_DETAIL.txt` |
| Call Graph | ✓ | ✓ | `ALL_CALL_GRAPH.txt` |
| String Xrefs | ✓ | ✓ | `ALL_STRING_XREFS.txt` |
| Data Variables | ✓ | ✓ | `ALL_DATA_VARIABLES.txt` |
| Comments | ✓ | ✓ | `ALL_COMMENTS.txt` / `ALL_COMMENTS_TAGS.txt` |
| Types (full type library) | ✓ | ✓ | `ALL_TYPES.txt` |
| Structures | ✓ | ✓ | `ALL_STRUCTURES.txt` |
| VTables | ✓ | ✓ | `ALL_VTABLES.txt` |
| RTTI | ✓ | ✓ | `ALL_RTTI.txt` |
| IL Pipeline (LLIL→MLIL→HLIL) | — | ✓ | `ALL_IL_PIPELINE.txt` |
| Problems / Warnings | ✓ | — | `ALL_PROBLEMS.txt` |
| Try/Catch / SEH Blocks | ✓ | — | `ALL_TRYBLKS.txt` |
| Fixups / Relocations | ✓ | — | `ALL_FIXUPS.txt` |
| Patched Bytes | ✓ | — | `ALL_PATCHED_BYTES.txt` |
| Hidden / Collapsed Ranges | ✓ | — | `ALL_HIDDEN_RANGES.txt` |
| Bookmarks | ✓ | — | `ALL_BOOKMARKS.txt` |
| Switch / Jump Tables | ✓ | — | `ALL_SWITCH_TABLES.txt` |

**IDA: 25 dump types** — leverages the full IDA 9.x Python SDK (`ida_hexrays`, `ida_typeinf`, `ida_nalt`, `ida_tryblks`, `ida_fixup`, etc.).

**Binary Ninja: 19 dump types** — uses Binary Ninja's HLIL decompiler with 6-strategy fallback, plus the full IL pipeline (LLIL → MLIL → MLIL-SSA → HLIL).

---

## Key Behaviors

- **Decompiled = decompiled only.** `ALL_DECOMPILED.c` contains only successfully decompiled pseudocode. Functions that fail decompilation are skipped — no assembly fallback pollutes the `.c` file. Assembly is in `ALL_ASSEMBLY.asm`.
- **Skip-existing.** `Dump EVERYTHING` checks each output file before re-dumping. If a file already exists and the function count matches the current database, it is skipped. This makes incremental re-runs fast.
- **Zero truncation.** All output is dumped in full. The lookup tools print every match — no `... N more results ...` cutoffs.
- **Progress logging.** Both plugins log percentage progress and are cancellable during long dumps.

---

## IDA Pro Plugin

### Requirements

- IDA Pro 9.0+ with Hex-Rays decompiler
- Python 3.x (bundled with IDA)

### Installation

Copy the plugin to your IDA plugins directory:

| OS | Path |
|---|---|
| Windows | `C:\Program Files\IDA Professional 9.x\plugins\` |
| Linux | `~/.idapro/plugins/` |
| macOS | `~/.idapro/plugins/` |

```bash
cp ida/DumpToolkit.py <IDA_PLUGINS_DIR>/DumpToolkit.py
```

The plugin loads automatically when IDA starts. Look for `[Ida Dumper] Ready! 25 dump types.` in the output window.

### Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl-Shift-D` | Dump EVERYTHING (all 25 dump types) |
| `Ctrl-Shift-A` | Copy current function's assembly to clipboard |
| `Ctrl-Shift-C` | Copy current function's decompiled pseudocode to clipboard |
| `Ctrl-Shift-X` | Copy ALL (assembly + decompiled) to clipboard |

Additional dump actions are available from the right-click context menu: **DumpToolkit → Dump Assembly / Decompiled / Overview / ...** (all 25 types individually).

### 25 Dump Types

| # | Dump | Description |
|---|---|---|
| 1 | Assembly | Full disassembly of every function |
| 2 | Decompiled | Hex-Rays pseudocode for every function (failures skipped) |
| 3 | Overview | Binary metadata — entry point, architecture, file hashes, segment map, stats |
| 4 | Function Details | Per-function: address, size, frame size, flags, local variables, stack vars, register vars |
| 5 | Call Graph | Complete caller→callee adjacency list |
| 6 | String Xrefs | Which functions reference each string |
| 7 | Data Variables | Globals, statics, named data with types and values |
| 8 | Comments | All comments (regular, repeatable, function, anterior, posterior) |
| 9 | Types | Full local type library — structs, unions, enums, typedefs, function prototypes |
| 10 | Strings | All strings with addresses and types |
| 11 | Names | All named addresses / symbols |
| 12 | Imports | Imported functions grouped by module |
| 13 | Exports | Exported symbols with ordinals |
| 14 | Segments | Segment layout with permissions, classes, and sizes |
| 15 | VTables | C++ virtual function tables with resolved slot names |
| 16 | RTTI | C++ RTTI class hierarchy (`Complete Object Locator`, `TypeDescriptor`, inheritance chains) |
| 17 | Xrefs | Cross-references for every function (code refs, data refs, callers, callees) |
| 18 | Structures | Struct/union/enum definitions with member offsets and types |
| 19 | Problems | IDA-flagged issues (auto-analysis warnings, conversion errors) |
| 20 | Try/Catch | SEH / C++ exception handling blocks (`try_from`→`try_to`, handlers, catch types) |
| 21 | Fixups | Relocation entries (fixup types, targets, base addresses) |
| 22 | Patched Bytes | All manually patched bytes (original → patched values) |
| 23 | Hidden Ranges | Collapsed/hidden code regions |
| 24 | Bookmarks | User-set bookmarks with descriptions |
| 25 | Switch Tables | Jump table analysis (cases, targets, default branches) |

### IDA Lookup Tool

```bash
cd ida/
python ida_lookup.py <command> [arguments]
```

**Commands:**

```bash
# Extract function — ASM + decompiled + callers + callees + xrefs
python ida_lookup.py func 7FF6FDB8EFA0

# Search across ALL 25 dump files
python ida_lookup.py search "CreateFile|OpenFile"

# Targeted searches
python ida_lookup.py strings "password|secret|key"
python ida_lookup.py strxrefs "AES|encrypt"
python ida_lookup.py xrefs 7FF6FDB8EFA0
python ida_lookup.py callers 7FF6FF42BCB0
python ida_lookup.py callees 7FF6FF42BCB0
python ida_lookup.py callgraph 7FF6FDB8EFA0
python ida_lookup.py overview
python ida_lookup.py types "SOCKET|HANDLE"
python ida_lookup.py datavars "g_config"
python ida_lookup.py funcdetail 7FF6FDB8EFA0
python ida_lookup.py comments "TODO|FIXME"
python ida_lookup.py imports "Crypt|Socket"
python ida_lookup.py exports "DllMain"
python ida_lookup.py segments
python ida_lookup.py vtables "CObject"
python ida_lookup.py rtti "CBase"
python ida_lookup.py structures "HEADER"
python ida_lookup.py names "sub_|loc_"

# File utilities
python ida_lookup.py read c 100 200           # Read lines 100-200 of decompiled
python ida_lookup.py grep "malloc" asm         # Grep in assembly file
python ida_lookup.py around c 5000 50          # 50 lines around line 5000
```

**File aliases:** `c`/`decompiled`/`pseudo`/`hexrays`, `asm`/`assembly`/`disasm`, `strings`/`str`, `xrefs`/`crossrefs`, `names`/`symbols`, `vtables`/`vftable`, `rtti`/`classes`/`typeinfo`, `segments`/`sections`, `imports`/`imp`, `exports`/`exp`, `structures`/`struct`, `types`/`typedef`, `overview`/`triage`/`info`, `func_details`/`funcdetails`/`details`, `call_graph`/`callgraph`/`graph`, `string_xrefs`/`stringxrefs`, `data_vars`/`datavars`/`globals`, `comments`/`cmt`, `problems`/`issues`/`errors`, `tryblks`/`trycatch`/`seh`/`exceptions`, `fixups`/`relocs`, `patched_bytes`/`patches`, `hidden_ranges`/`hidden`/`collapsed`, `bookmarks`/`marks`, `switch_tables`/`switch`/`jumptable`

---

## Binary Ninja Plugin

### Requirements

- Binary Ninja (tested on v5.x)
- Python 3.x (bundled with Binary Ninja)

### Installation

Copy the plugin to your Binary Ninja plugins directory:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |

```bash
cp binja/BinjaDumpToolkit.py <BINJA_PLUGINS_DIR>/
```

The plugin auto-registers on load. Access via **Plugins → BinjaDumpToolkit** or right-click a function.

### 19 Dump Types

**From the Plugins menu (BinaryView-level):**

| # | Dump | Description |
|---|---|---|
| 1 | Overview | Architecture, file hashes, section map, entry points, stats |
| 2 | Assembly | Full disassembly of every function |
| 3 | Decompiled | HLIL pseudocode with recovered types & local vars (failures skipped) |
| 4 | IL Pipeline | LLIL → MLIL → MLIL-SSA → HLIL per function (the deobfuscation dump) |
| 5 | Strings | All strings with addresses |
| 6 | Names | All named symbols |
| 7 | Imports | Imported functions by module |
| 8 | Exports | Exported symbols |
| 9 | Segments | Section/segment layout |
| 10 | Xrefs | Cross-references (callers/callees) |
| 11 | Function Details | Locals, stack frame, calling convention, parameters |
| 12 | Call Graph | Complete caller→callee adjacency list |
| 13 | String Xrefs | String→function cross-reference map |
| 14 | Data Variables | Global/static data with types and values |
| 15 | Comments/Tags | Function/address comments + Binary Ninja tags |
| 16 | Structures | Struct/union/enum definitions |
| 17 | Full Types | Full type library — structs, enums, typedefs, function pointers, arrays |
| 18 | RTTI | C++ RTTI class hierarchy |
| 19 | VTables | C++ virtual function tables |

**Dump EVERYTHING** runs all 19 sequentially with skip-existing checks.

**Right-click a function:**
- Copy Assembly / Copy Decompiled / Copy ALL (asm + decompiled + IL pipeline)
- Dump Function Assembly / Decompiled / Xrefs / IL Pipeline / Full

### Binja Lookup Tool

```bash
cd binja/
python binja_lookup.py <command> [arguments]
```

**Commands:**

```bash
# Extract function — ASM + decompiled + IL + details + callers + callees
python binja_lookup.py func 7FF6FDB8EFA0

# Search across ALL 19 dump files
python binja_lookup.py search "OpenRequest2"

# Targeted searches
python binja_lookup.py strings "ChaCha20|AES-GCM"
python binja_lookup.py strxrefs "password"
python binja_lookup.py xrefs 7FF6FDB71C20
python binja_lookup.py callers 7FF6FF42BCB0
python binja_lookup.py callees 7FF6FF42BCB0
python binja_lookup.py il 7FF6FDB8EFA0
python binja_lookup.py callgraph 7FF6FDB8EFA0
python binja_lookup.py funcdetail 7FF6FDB8EFA0
python binja_lookup.py overview
python binja_lookup.py types "SOCKET|sockaddr"
python binja_lookup.py datavars "g_config"
python binja_lookup.py comments "TODO|fixme"
python binja_lookup.py imports "Crypt|Socket"
python binja_lookup.py exports "DllMain"
python binja_lookup.py segments
python binja_lookup.py vtables "CObject"
python binja_lookup.py rtti "CBase"
python binja_lookup.py structures "HEADER"
python binja_lookup.py names "sub_|loc_"

# File utilities
python binja_lookup.py read c 100 200
python binja_lookup.py grep "CreateFile" asm
python binja_lookup.py around c 5000 50
```

**File aliases:** `c`/`decompiled`, `asm`/`assembly`, `strings`/`string`, `strxrefs`/`string_xrefs`/`stringxrefs`, `xrefs`/`xref`, `names`/`name`, `vtables`/`vtable`, `rtti`, `segments`/`segment`, `imports`/`import`, `exports`/`export`, `structures`/`struct`, `types`/`typedef`, `overview`/`triage`/`info`, `datavars`/`data_vars`/`vars`, `callgraph`/`call_graph`/`graph`, `funcdetails`/`func_details`/`functions`, `comments`/`tags`, `il`/`pipeline`/`llil`/`mlil`/`hlil`

---

## Output Structure

Both toolkits dump to a directory next to the analyzed binary:

```
<binary_directory>/
└── IDA_DUMPS/ or BINJA_DUMPS/
    ├── ALL_ASSEMBLY.asm
    ├── ALL_DECOMPILED.c
    ├── ALL_OVERVIEW.txt
    ├── ALL_STRINGS.txt
    ├── ALL_NAMES.txt
    ├── ALL_IMPORTS.txt
    ├── ALL_EXPORTS.txt
    ├── ALL_SEGMENTS.txt
    ├── ALL_XREFS.txt
    ├── ALL_FUNCTION_DETAILS.txt
    ├── ALL_CALL_GRAPH.txt
    ├── ALL_STRING_XREFS.txt
    ├── ALL_DATA_VARIABLES.txt
    ├── ALL_COMMENTS.txt
    ├── ALL_TYPES.txt
    ├── ALL_STRUCTURES.txt
    ├── ALL_VTABLES.txt
    ├── ALL_RTTI.txt
    ├── ALL_IL_PIPELINE.txt         # Binja only
    ├── ALL_PROBLEMS.txt            # IDA only
    ├── ALL_TRYBLKS.txt             # IDA only
    ├── ALL_FIXUPS.txt              # IDA only
    ├── ALL_PATCHED_BYTES.txt       # IDA only
    ├── ALL_HIDDEN_RANGES.txt       # IDA only
    ├── ALL_BOOKMARKS.txt           # IDA only
    ├── ALL_SWITCH_TABLES.txt       # IDA only
    ├── function_dumps/             # Individual function files
    └── function_xrefs/             # Individual xref files
```

## Workflow

1. **Open binary** in IDA or Binary Ninja
2. **Wait for analysis** to complete
3. **Dump everything** — `Ctrl-Shift-D` (IDA) or Plugins → BinjaDumpToolkit → Dump EVERYTHING
4. **Analyze offline** with the lookup tool:
   ```bash
   python ida_lookup.py search "encrypt"
   python ida_lookup.py func 140001000
   python ida_lookup.py callers 140002500
   ```

## License

Please respect the licensing terms of IDA Pro and Binary Ninja when using these tools.

## Contributing

Issues and PRs welcome.
