# IDA Plugins Kit

A comprehensive toolkit for IDA Pro that includes powerful plugins for dumping and analyzing binary executables.

## Overview

This repository contains two main components:

1. **DumpToolkit.py** - An IDA Pro plugin that dumps comprehensive information from loaded binaries
2. **ida_lookup.py** - A command-line tool for searching and analyzing the dumped data

## Requirements

- **IDA Pro 9.0+** (or compatible versions)
- **Python 3.x** (for ida_lookup.py)
- **Hex-Rays Decompiler** (optional, required for decompiled code dumps)

## Installation

### Installing DumpToolkit Plugin

1. **Locate your IDA plugins directory:**
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Linux: `~/.idapro/plugins/`
   - macOS: `~/.idapro/plugins/`
   
   Alternatively, use IDA's installation directory:
   - `<IDA_INSTALLATION_DIR>/plugins/`

2. **Copy the plugin:**
   ```bash
   cp DumpToolkit.py <IDA_PLUGINS_DIR>/
   ```

3. **Restart IDA Pro**
   
   The plugin will automatically load and display:
   ```
   [DumpTookit] Initializing...
   [DumpTookit] Ready! Right-click for options or Ctrl-Shift-D to dump everything.
   ```

### Installing ida_lookup.py

The lookup tool is a standalone Python script that doesn't require installation. Simply ensure Python 3.x is installed:

```bash
python3 --version  # Verify Python 3 is installed
```

## Usage

### DumpToolkit Plugin

Once installed, DumpToolkit adds multiple options to IDA Pro's right-click context menu:

#### Quick Dump Everything

Press **Ctrl-Shift-D** to dump all available information from the binary.

#### Context Menu Options

Right-click anywhere in IDA to access these features:

**Copy Actions (for current selection):**
- **Copy Assembly** (Ctrl-Shift-A) - Copy current function's assembly to clipboard
- **Copy Decompiled** (Ctrl-Shift-C) - Copy current function's decompiled code to clipboard
- **Copy ALL** (Ctrl-Shift-X) - Copy both assembly and decompiled code to clipboard
- **Copy String** - Copy string at current location to clipboard

**Single Function Dumps:**
- **Dump Function Assembly** - Save current function's assembly to file
- **Dump Function Decompiled** - Save current function's decompiled code to file
- **Dump Function Xrefs** - Save all cross-references for current function
- **Dump Function (Full)** - Save complete dump of current function

**Dump ALL Actions:**
- **Dump ALL Assembly (.asm)** - Dump all functions as assembly code
- **Dump ALL Decompiled (.c)** - Dump all functions as decompiled C code
- **Dump ALL Strings** - Dump all strings found in the binary
- **Dump ALL Names** - Dump all named addresses
- **Dump ALL Imports** - Dump all imported functions
- **Dump ALL Exports** - Dump all exported functions
- **Dump ALL Segments** - Dump memory segment information
- **Dump ALL VTables** - Dump all virtual function tables
- **Dump ALL RTTI** - Dump Run-Time Type Information
- **Dump ALL Xrefs** - Dump all cross-references
- **Dump ALL Structures** - Dump all structure definitions
- **Dump EVERYTHING** - Perform all dumps at once

#### Output Location

All dumps are saved to the `IDA_DUMPS` directory in the same location as your input file:

```
<input_file_directory>/
└── IDA_DUMPS/
    ├── ALL_ASSEMBLY.asm
    ├── ALL_DECOMPILED.c
    ├── ALL_STRINGS.txt
    ├── ALL_NAMES.txt
    ├── ALL_IMPORTS.txt
    ├── ALL_EXPORTS.txt
    ├── ALL_SEGMENTS.txt
    ├── ALL_VTABLES.txt
    ├── ALL_RTTI.txt
    ├── ALL_XREFS.txt
    ├── ALL_STRUCTURES.txt
    └── functions/
        ├── sub_140001000_ASM.txt
        ├── sub_140001000_DECOMPILED.txt
        └── ...
```

### ida_lookup.py Tool

The lookup tool provides powerful search capabilities across all dumped files.

#### Basic Usage

```bash
python ida_lookup.py <command> [arguments]
```

#### Available Commands

**Extract Function:**
```bash
python ida_lookup.py func <address>
# Example: python ida_lookup.py func 7FF6FDB8EFA0
# Extracts both assembly and decompiled code for the function at the specified address
```

**Search All Files:**
```bash
python ida_lookup.py search <pattern>
# Example: python ida_lookup.py search "OpenRequest2"
# Searches for the pattern across all dump files
```

**Search Strings:**
```bash
python ida_lookup.py strings <pattern>
# Example: python ida_lookup.py strings "ChaCha20|AES-GCM"
# Searches only in ALL_STRINGS.txt using regex pattern
```

**Find Cross-References:**
```bash
python ida_lookup.py xrefs <address>
# Example: python ida_lookup.py xrefs 7FF6FDB71C20
# Finds all cross-references to/from the specified address
```

**Find Function Callers:**
```bash
python ida_lookup.py callers <address>
# Example: python ida_lookup.py callers 7FF6FF42BCB0
# Shows all functions that call the specified function
```

**Find Function Callees:**
```bash
python ida_lookup.py callees <address>
# Example: python ida_lookup.py callees 7FF6FF42BCB0
# Shows all functions called by the specified function
```

**Read Specific Lines:**
```bash
python ida_lookup.py read <file> <start> <end>
# Example: python ida_lookup.py read ALL_DECOMPILED.c 6676900 6677100
# Reads lines from start to end in the specified file
```

**Grep in File:**
```bash
python ida_lookup.py grep <pattern> <file>
# Example: python ida_lookup.py grep "case 0x78" ALL_DECOMPILED.c
# Searches for pattern in a specific file
```

**Read Context Around Line:**
```bash
python ida_lookup.py around <file> <line> [context]
# Example: python ida_lookup.py around ALL_DECOMPILED.c 6676949 50
# Reads 50 lines before and after line 6676949
```

#### File Aliases

The lookup tool supports convenient file aliases:
- `c`, `decompiled`, `decompile` → ALL_DECOMPILED.c
- `asm`, `assembly` → ALL_ASSEMBLY.asm
- `strings`, `string` → ALL_STRINGS.txt
- `xrefs`, `xref` → ALL_XREFS.txt
- `names`, `name` → ALL_NAMES.txt
- `vtables`, `vtable` → ALL_VTABLES.txt

## Workflow Example

### Complete Analysis Workflow

1. **Open your binary in IDA Pro**

2. **Let IDA complete its analysis**
   
3. **Dump everything:**
   - Press `Ctrl-Shift-D`
   - Or right-click → "Dump EVERYTHING"
   
4. **Analyze dumps with ida_lookup.py:**
   ```bash
   # Search for interesting functions
   python ida_lookup.py search "crypto"
   
   # Look up a specific function
   python ida_lookup.py func 140001000
   
   # Find all strings containing "password"
   python ida_lookup.py strings "password"
   
   # Find who calls a sensitive function
   python ida_lookup.py callers 140002500
   ```

### Quick Function Analysis

1. **In IDA, navigate to a function**

2. **Right-click → "Dump Function (Full)"**

3. **Use ida_lookup.py to explore:**
   ```bash
   # View the function
   python ida_lookup.py func <address>
   
   # See who calls it
   python ida_lookup.py callers <address>
   
   # See what it calls
   python ida_lookup.py callees <address>
   ```

## Features

### DumpToolkit Features

- ✅ Dump all functions (assembly and decompiled)
- ✅ Extract strings with cross-references
- ✅ Export all symbols, imports, and exports
- ✅ Extract virtual tables (VTables)
- ✅ Dump RTTI information for C++ classes
- ✅ Save all cross-references
- ✅ Export structure definitions
- ✅ Clipboard integration for quick copying
- ✅ Keyboard shortcuts for common actions
- ✅ Progress indicators with user cancellation support
- ✅ Context menu integration

### ida_lookup Features

- ✅ Fast regex-based searching
- ✅ Function extraction by address
- ✅ Cross-reference analysis
- ✅ Call graph exploration (callers/callees)
- ✅ Targeted file searching with aliases
- ✅ Context-aware line reading
- ✅ Multi-file pattern searching

## Troubleshooting

### Plugin not loading

1. Verify the plugin is in the correct directory
2. Check IDA's output window for error messages
3. Ensure you're using IDA Pro 9.0 or compatible version

### Hex-Rays decompiler not available

- Decompiled dumps require the Hex-Rays decompiler plugin
- If not available, assembly dumps will still work
- The plugin will display: `[DumpTookit] Hex-Rays decompiler not available!`

### ida_lookup.py can't find files

1. Ensure you've run dumps from DumpToolkit first
2. By default, ida_lookup.py looks for a `DUMP/` directory in the script's location
3. Modify the `DUMP_DIR` variable in ida_lookup.py if your dumps are elsewhere:
   ```python
   DUMP_DIR = Path("/path/to/your/IDA_DUMPS")
   ```

## Tips and Best Practices

1. **Dump early, dump often** - Create dumps after major analysis milestones
2. **Use targeted dumps** - For single functions, use specific dump commands instead of dumping everything
3. **Leverage regex** - The lookup tool supports powerful regex patterns for complex searches
4. **Organize dumps** - Consider creating separate dump directories for different analysis sessions
5. **Clipboard shortcuts** - Use Ctrl-Shift-A/C/X for quick copying during analysis

## License

This is a collection of IDA Pro plugins and tools. Please respect IDA Pro's licensing terms when using these tools.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.
