#!/usr/bin/env python3
"""
IDA Dump Lookup Tool - Comprehensive search across ALL IDA dump files.

Usage:
  python ida_lookup.py func <address>              # Extract function (ASM + C + xrefs + strings)
  python ida_lookup.py search <pattern>            # Search ALL files for pattern
  python ida_lookup.py strings <pattern>           # Search ALL_STRINGS.txt
  python ida_lookup.py strxrefs <pattern>          # Search string cross-references via xrefs
  python ida_lookup.py xrefs <address>             # Find all xrefs to/from address
  python ida_lookup.py callers <address>           # Who calls this function?
  python ida_lookup.py callees <address>           # What does this function call?
  python ida_lookup.py callgraph <address>         # Full call graph (callers + callees from xrefs file)
  python ida_lookup.py overview                    # Show binary overview / triage info
  python ida_lookup.py types <pattern>             # Search structures/types
  python ida_lookup.py datavars <pattern>          # Search data variables / globals
  python ida_lookup.py funcdetail <address>        # Detailed function info (locals, calls, strings)
  python ida_lookup.py comments <pattern>          # Search comments in asm/decompiled
  python ida_lookup.py imports <pattern>           # Search imports
  python ida_lookup.py exports <pattern>           # Search exports
  python ida_lookup.py segments                    # List all segments
  python ida_lookup.py vtables <pattern>           # Search vtables
  python ida_lookup.py rtti <pattern>              # Search RTTI / class info
  python ida_lookup.py structures <pattern>        # Search structures
  python ida_lookup.py names <pattern>             # Search named addresses
  python ida_lookup.py read <file> <start> <end>   # Read line range from file
  python ida_lookup.py grep <pattern> <file>       # Grep pattern in specific file
  python ida_lookup.py around <file> <line> [ctx]  # Read lines around a line number

Examples:
  python ida_lookup.py func 7FF6FDB8EFA0
  python ida_lookup.py search "OpenRequest2"
  python ida_lookup.py strings "ChaCha20|AES-GCM"
  python ida_lookup.py strxrefs "password"
  python ida_lookup.py xrefs 7FF6FDB71C20
  python ida_lookup.py callers 7FF6FF42BCB0
  python ida_lookup.py callgraph 7FF6FF42BCB0
  python ida_lookup.py overview
  python ida_lookup.py types "SOCKET_CONTEXT"
  python ida_lookup.py datavars "g_global"
  python ida_lookup.py funcdetail 7FF6FDB8EFA0
  python ida_lookup.py comments "TODO|FIXME|hack"
  python ida_lookup.py imports "Crypt"
  python ida_lookup.py exports "DllMain"
  python ida_lookup.py segments
  python ida_lookup.py vtables "CBase"
  python ida_lookup.py rtti "CBase"
  python ida_lookup.py structures "HEADER"
  python ida_lookup.py names "sub_7FF"
  python ida_lookup.py read ALL_DECOMPILED.c 6676900 6677100
  python ida_lookup.py grep "case 0x78" ALL_DECOMPILED.c
  python ida_lookup.py around ALL_DECOMPILED.c 6676949 50
"""

import sys
import re
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import argparse

# Configuration — auto-detect dump directory
DUMP_DIR = Path(__file__).parent / "DUMP"
if not DUMP_DIR.exists():
    # Fallback: check IDA_DUMPS
    DUMP_DIR = Path(__file__).parent / "IDA_DUMPS"
OUTPUT_DIR = DUMP_DIR / "extracted"

# ============================================================================
# FILE MAP — every single dump file IDA DumpToolkit produces
# ============================================================================

FILES = {
    'asm': DUMP_DIR / "ALL_ASSEMBLY.asm",
    'c': DUMP_DIR / "ALL_DECOMPILED.c",
    'strings': DUMP_DIR / "ALL_STRINGS.txt",
    'xrefs': DUMP_DIR / "ALL_XREFS.txt",
    'names': DUMP_DIR / "ALL_NAMES.txt",
    'vtables': DUMP_DIR / "ALL_VTABLES.txt",
    'rtti': DUMP_DIR / "ALL_RTTI.txt",
    'segments': DUMP_DIR / "ALL_SEGMENTS.txt",
    'imports': DUMP_DIR / "ALL_IMPORTS.txt",
    'exports': DUMP_DIR / "ALL_EXPORTS.txt",
    'structures': DUMP_DIR / "ALL_STRUCTURES.txt",
    'overview': DUMP_DIR / "ALL_OVERVIEW.txt",
    'func_details': DUMP_DIR / "ALL_FUNCTION_DETAILS.txt",
    'call_graph': DUMP_DIR / "ALL_CALL_GRAPH.txt",
    'string_xrefs': DUMP_DIR / "ALL_STRING_XREFS.txt",
    'data_vars': DUMP_DIR / "ALL_DATA_VARIABLES.txt",
    'comments': DUMP_DIR / "ALL_COMMENTS.txt",
    'types': DUMP_DIR / "ALL_TYPES.txt",
    'problems': DUMP_DIR / "ALL_PROBLEMS.txt",
    'tryblks': DUMP_DIR / "ALL_TRYBLKS.txt",
    'fixups': DUMP_DIR / "ALL_FIXUPS.txt",
    'patched_bytes': DUMP_DIR / "ALL_PATCHED_BYTES.txt",
    'hidden_ranges': DUMP_DIR / "ALL_HIDDEN_RANGES.txt",
    'bookmarks': DUMP_DIR / "ALL_BOOKMARKS.txt",
    'switch_tables': DUMP_DIR / "ALL_SWITCH_TABLES.txt",
}

# ============================================================================
# ALIASES — every conceivable shorthand
# ============================================================================

FILE_ALIASES = {
    # Decompiled
    'decompiled': 'c',
    'decompile': 'c',
    'dec': 'c',
    'pseudo': 'c',
    'pseudocode': 'c',
    'hexrays': 'c',
    # Assembly
    'assembly': 'asm',
    'disasm': 'asm',
    'disassembly': 'asm',
    # Strings
    'string': 'strings',
    'str': 'strings',
    # Xrefs
    'xref': 'xrefs',
    'crossref': 'xrefs',
    'crossrefs': 'xrefs',
    # Names
    'name': 'names',
    'symbols': 'names',
    'symbol': 'names',
    # VTables
    'vtable': 'vtables',
    'vftable': 'vtables',
    'vft': 'vtables',
    # RTTI
    'class': 'rtti',
    'classes': 'rtti',
    'typeinfo': 'rtti',
    # Segments
    'segment': 'segments',
    'sections': 'segments',
    'section': 'segments',
    'segs': 'segments',
    # Imports
    'import': 'imports',
    'imp': 'imports',
    # Exports
    'export': 'exports',
    'exp': 'exports',
    # Structures
    'struct': 'structures',
    'structure': 'structures',
    'structs': 'structures',
    'types': 'types',
    'type': 'types',
    'typedef': 'types',
    # Overview
    'info': 'overview',
    'binary': 'overview',
    'triage': 'overview',
    'summary': 'overview',
    # Function details
    'funcdetails': 'func_details',
    'funcinfo': 'func_details',
    'funcdet': 'func_details',
    'details': 'func_details',
    # Call graph
    'callgraph': 'call_graph',
    'calls': 'call_graph',
    'graph': 'call_graph',
    # String xrefs
    'stringxrefs': 'string_xrefs',
    'strxref': 'string_xrefs',
    'stringrefs': 'string_xrefs',
    # Data variables
    'datavars': 'data_vars',
    'data': 'data_vars',
    'globals': 'data_vars',
    'vars': 'data_vars',
    'variables': 'data_vars',
    # Comments
    'comment': 'comments',
    'cmt': 'comments',
    'cmts': 'comments',
    # Problems
    'problem': 'problems',
    'issues': 'problems',
    'errors': 'problems',
    # Try/catch
    'tryblk': 'tryblks',
    'trycatch': 'tryblks',
    'exceptions': 'tryblks',
    'seh': 'tryblks',
    # Fixups
    'fixup': 'fixups',
    'relocs': 'fixups',
    'relocations': 'fixups',
    # Patched bytes
    'patches': 'patched_bytes',
    'patched': 'patched_bytes',
    'patch': 'patched_bytes',
    # Hidden ranges
    'hidden': 'hidden_ranges',
    'collapsed': 'hidden_ranges',
    # Bookmarks
    'bookmark': 'bookmarks',
    'marks': 'bookmarks',
    'marked': 'bookmarks',
    # Switch tables
    'switch': 'switch_tables',
    'jumptable': 'switch_tables',
    'jumptables': 'switch_tables',
}


def get_file_path(name: str) -> Path:
    """Get file path from name or alias."""
    name_lower = name.lower()

    if name_lower in FILE_ALIASES:
        name_lower = FILE_ALIASES[name_lower]

    if name_lower in FILES:
        return FILES[name_lower]

    # Direct filename
    direct = DUMP_DIR / name
    if direct.exists():
        return direct

    # Try .txt
    txt = DUMP_DIR / f"{name}.txt"
    if txt.exists():
        return txt

    return None


def normalize_address(addr: str) -> str:
    """Normalize address to uppercase hex."""
    addr = addr.upper().strip()
    for prefix in ['SUB_', '0X', 'LOC_', 'FUNC_']:
        if addr.startswith(prefix):
            addr = addr[len(prefix):]
    return addr


# ============================================================================
# CORE SEARCH — ZERO TRUNCATION
# ============================================================================

def read_lines(filepath: Path, start: int, end: int) -> List[str]:
    """Read specific line range from file (1-indexed). NO LIMITS."""
    if not filepath.exists():
        print(f"Error: File not found: {filepath}")
        return []

    lines = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            if i >= start:
                lines.append(f"{i:8d}: {line.rstrip()}")
            if i >= end:
                break
    return lines


def search_file(filepath: Path, pattern: str, is_regex: bool = True,
                max_results: int = 0, context: int = 0) -> List[Dict]:
    """Search for pattern in file. max_results=0 means UNLIMITED."""
    if not filepath.exists():
        return []

    if is_regex:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print(f"Invalid regex: {e}")
            return []

    results = []
    context_buffer = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if context > 0:
                context_buffer.append((line_num, line.rstrip()))
                if len(context_buffer) > context * 2 + 1:
                    context_buffer.pop(0)

            if is_regex:
                match = regex.search(line)
            else:
                match = pattern.lower() in line.lower()

            if match:
                result = {
                    'line_num': line_num,
                    'line': line.rstrip(),  # FULL LINE — NO TRUNCATION
                    'file': filepath.name
                }
                if context > 0:
                    result['context_before'] = context_buffer[:-1][-context:]
                results.append(result)

                if max_results > 0 and len(results) >= max_results:
                    break

    return results


def search_all_files(pattern: str, is_regex: bool = True, max_per_file: int = 0) -> Dict[str, List]:
    """Search pattern across ALL dump files. max_per_file=0 means UNLIMITED."""
    all_results = {}

    for name, filepath in FILES.items():
        if filepath.exists():
            results = search_file(filepath, pattern, is_regex, max_per_file)
            if results:
                all_results[name] = results

    return all_results


# ============================================================================
# FUNCTION EXTRACTION — NO LINE LIMITS, NO TRUNCATION
# ============================================================================

def extract_function_asm(address: str) -> Optional[str]:
    """Extract assembly function. NO LINE LIMIT."""
    filepath = FILES['asm']
    if not filepath.exists():
        return None

    lines = []
    in_function = False
    func_header = f"; Function: sub_{address}".upper()

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if not in_function:
                if func_header in line.upper():
                    in_function = True
                    lines.append(f"; === Line {line_num} ===\n")
                    lines.append(line)
            else:
                if line.upper().startswith("; FUNCTION: SUB_") and f"SUB_{address}" not in line.upper():
                    break
                if line.strip().startswith(";---") and len(lines) > 10:
                    lines.append(line)
                    break
                lines.append(line)

    return ''.join(lines) if lines else None


def extract_function_c(address: str) -> Optional[str]:
    """Extract decompiled C function. NO LINE LIMIT."""
    filepath = FILES['c']
    if not filepath.exists():
        return None

    lines = []
    in_function = False
    brace_count = 0
    found_body = False
    func_header = f"// Function: sub_{address}".upper()
    separator = "/------------------------------------------------------------------------------/"

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if not in_function:
                if func_header in line.upper():
                    in_function = True
                    lines.append(f"// === Line {line_num} ===\n")
                    lines.append(line)
            else:
                if separator in line and found_body and brace_count <= 0:
                    break
                if "// Function: sub_" in line and func_header not in line.upper():
                    if found_body and brace_count <= 0:
                        break

                lines.append(line)
                brace_count += line.count('{') - line.count('}')
                if '{' in line:
                    found_body = True

                if found_body and brace_count <= 0 and len(lines) > 5:
                    break

    return ''.join(lines) if lines else None


# ============================================================================
# XREF / CALLER / CALLEE — NO LIMITS
# ============================================================================

def find_xrefs(address: str) -> Dict[str, List]:
    """Find cross-references to/from an address. NO LIMITS."""
    addr_upper = address.upper()
    results = {'to': [], 'from': [], 'data': []}

    # ALL xrefs from xrefs file
    xrefs_file = FILES['xrefs']
    if xrefs_file.exists():
        with open(xrefs_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if addr_upper in line.upper():
                    results['data'].append({
                        'line_num': line_num,
                        'line': line.strip()  # FULL LINE
                    })

    # ALL calls from ASM
    asm_file = FILES['asm']
    if asm_file.exists():
        call_pattern = re.compile(rf'(call|jmp|lea)\s+.*{addr_upper}', re.IGNORECASE)
        current_func = "unknown"

        with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if "; Function: sub_" in line:
                    match = re.search(r'sub_([0-9A-Fa-f]+)', line, re.IGNORECASE)
                    if match:
                        current_func = match.group(1).upper()

                if call_pattern.search(line):
                    results['to'].append({
                        'caller': current_func,
                        'line_num': line_num,
                        'line': line.strip()  # FULL LINE
                    })

    return results


def find_callers(address: str) -> List[Dict]:
    """Find ALL functions that call this address. NO LIMITS."""
    addr_upper = address.upper()
    callers = []
    seen = set()

    asm_file = FILES['asm']
    if not asm_file.exists():
        return callers

    current_func = None
    func_line = 0
    pattern = re.compile(rf'call\s+.*sub_{addr_upper}', re.IGNORECASE)

    with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if "; Function: sub_" in line:
                match = re.search(r'sub_([0-9A-Fa-f]+)', line, re.IGNORECASE)
                if match:
                    current_func = match.group(1).upper()
                    func_line = line_num

            if current_func and pattern.search(line):
                if current_func not in seen:
                    seen.add(current_func)
                    callers.append({
                        'address': current_func,
                        'func_line': func_line,
                        'call_line': line_num,
                        'instruction': line.strip()  # FULL LINE
                    })

    return callers


def find_callees(address: str) -> List[Dict]:
    """Find ALL functions called by this address. NO LIMITS."""
    asm_content = extract_function_asm(address)
    if not asm_content:
        return []

    callees = []
    seen = set()
    pattern = re.compile(r'call\s+sub_([0-9A-Fa-f]+)', re.IGNORECASE)

    for line in asm_content.split('\n'):
        match = pattern.search(line)
        if match:
            callee = match.group(1).upper()
            if callee not in seen:
                seen.add(callee)
                callees.append({
                    'address': callee,
                    'instruction': line.strip()  # FULL LINE
                })

    return callees


def search_strings(pattern: str, max_results: int = 0) -> List[Dict]:
    """Search in ALL_STRINGS.txt. UNLIMITED by default."""
    return search_file(FILES['strings'], pattern, is_regex=True, max_results=max_results)


# ============================================================================
# COMMANDS — 22 total, covering EVERYTHING
# ============================================================================

def cmd_func(args):
    """Extract EVERYTHING about a function."""
    address = normalize_address(args.address)
    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"Extracting function sub_{address}...")
    print()

    # ASM — FULL
    asm = extract_function_asm(address)
    if asm:
        out_file = OUTPUT_DIR / f"sub_{address}.asm"
        out_file.write_text(asm, encoding='utf-8')
        print(f"✓ ASM: {out_file.name} ({len(asm.splitlines())} lines)")
    else:
        print(f"✗ ASM not found")

    # C — FULL
    c = extract_function_c(address)
    if c:
        out_file = OUTPUT_DIR / f"sub_{address}.c"
        out_file.write_text(c, encoding='utf-8')
        print(f"✓ C:   {out_file.name} ({len(c.splitlines())} lines)")

        # Print ALL of it
        print("\n" + "=" * 80)
        print(c)
        print("=" * 80)
    else:
        print(f"✗ C not found")

    # ALL callers
    print(f"\nCallers of sub_{address}:")
    callers = find_callers(address)
    if callers:
        print(f"Found {len(callers)} callers:")
        for caller in callers:
            print(f"  sub_{caller['address']} (func line {caller['func_line']}, call line {caller['call_line']})")
    else:
        print("  None found")

    # ALL callees
    print(f"\nCallees of sub_{address}:")
    callees = find_callees(address)
    if callees:
        print(f"Calls {len(callees)} functions:")
        for callee in callees:
            print(f"  sub_{callee['address']}")
    else:
        print("  None found")

    # ALL xrefs from xrefs file
    xrefs_file = FILES['xrefs']
    if xrefs_file.exists():
        xref_results = search_file(xrefs_file, address, is_regex=False)
        if xref_results:
            print(f"\nXrefs ({len(xref_results)} entries):")
            for r in xref_results:
                print(f"  L{r['line_num']:>8}: {r['line']}")


def cmd_search(args):
    """Search ALL files, NO LIMITS."""
    pattern = args.pattern
    print(f"Searching all files for: '{pattern}'")
    print()

    limit = args.max or 0
    results = search_all_files(pattern, is_regex=True, max_per_file=limit)

    total_matches = 0
    for filename, matches in results.items():
        total_matches += len(matches)
        print(f"\n{'=' * 60}")
        print(f"  {filename.upper()} ({len(matches)} matches)")
        print('=' * 60)
        for m in matches:
            print(f"  L{m['line_num']:>8}: {m['line']}")

    print(f"\nTotal: {total_matches} matches across {len(results)} files")


def cmd_strings(args):
    """Search strings, NO LIMIT."""
    pattern = args.pattern
    print(f"Searching strings for: '{pattern}'")
    print()

    limit = args.max or 0
    results = search_strings(pattern, max_results=limit)

    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_strxrefs(args):
    """Search string cross-references."""
    pattern = args.pattern
    print(f"Searching string xrefs for: '{pattern}'")
    print()

    xrefs_file = FILES['xrefs']
    if not xrefs_file.exists():
        print("  ALL_XREFS.txt not found. Run DumpToolkit first.")
        return

    # Search xrefs file for the pattern
    results = search_file(xrefs_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} xref matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        # Search strings file, then look up xrefs for matching addresses
        str_results = search_strings(pattern, max_results=0)
        if str_results:
            print(f"Found {len(str_results)} matching strings, looking up xrefs:")
            for sr in str_results:
                addr_match = re.search(r'([0-9A-Fa-f]{8,16})', sr['line'])
                if addr_match:
                    addr = addr_match.group(1).upper()
                    xref_hits = search_file(xrefs_file, addr, is_regex=False, max_results=0)
                    print(f"\n  String L{sr['line_num']}: {sr['line']}")
                    if xref_hits:
                        for xr in xref_hits:
                            print(f"    Xref L{xr['line_num']}: {xr['line']}")
                    else:
                        print(f"    (no xrefs found for {addr})")
        else:
            print("  No matches found")


def cmd_xrefs(args):
    """Find ALL xrefs, NO LIMITS."""
    address = normalize_address(args.address)
    print(f"Finding xrefs for sub_{address}...")
    print()

    results = find_xrefs(address)

    if results['to']:
        print(f"Called BY ({len(results['to'])} refs):")
        for r in results['to']:
            print(f"  sub_{r['caller']:16} L{r['line_num']:>8}: {r['line']}")

    if results['data']:
        print(f"\nXREF data ({len(results['data'])} entries):")
        for r in results['data']:
            print(f"  L{r['line_num']:>8}: {r['line']}")

    if not results['to'] and not results['data']:
        print("  No xrefs found")


def cmd_callers(args):
    """Find ALL callers."""
    address = normalize_address(args.address)
    print(f"Finding callers of sub_{address}...")
    print()

    callers = find_callers(address)

    if callers:
        print(f"Found {len(callers)} callers:")
        for c in callers:
            print(f"  sub_{c['address']} (func line {c['func_line']}, call line {c['call_line']})")
            print(f"    {c['instruction']}")
    else:
        print("  No callers found")


def cmd_callees(args):
    """Find ALL callees."""
    address = normalize_address(args.address)
    print(f"Finding functions called by sub_{address}...")
    print()

    callees = find_callees(address)

    if callees:
        print(f"Calls {len(callees)} functions:")
        for c in callees:
            print(f"  sub_{c['address']}")
            print(f"    {c['instruction']}")
    else:
        print("  No callees found (or function not found)")


def cmd_callgraph(args):
    """Full call graph from xrefs file."""
    address = normalize_address(args.address)
    print(f"Call graph for sub_{address}...")
    print()

    xrefs_file = FILES['xrefs']
    if xrefs_file.exists():
        # Find the function block in xrefs file
        in_func = False
        func_pattern = re.compile(rf'\[FUNC\].*{address}', re.IGNORECASE)
        block_lines = []

        with open(xrefs_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if func_pattern.search(line):
                    in_func = True
                    block_lines.append(line.rstrip())
                    continue
                if in_func:
                    if line.startswith("[FUNC]"):
                        break
                    block_lines.append(line.rstrip())

        if block_lines:
            print(f"From ALL_XREFS.txt:")
            for bl in block_lines:
                print(f"  {bl}")
            print()

    # Also show ASM-based analysis
    callers = find_callers(address)
    callees = find_callees(address)

    if callers:
        print(f"\nCalled by ({len(callers)}):")
        for c in callers:
            print(f"  sub_{c['address']}")
    if callees:
        print(f"\nCalls ({len(callees)}):")
        for c in callees:
            print(f"  sub_{c['address']}")

    if not callers and not callees:
        print("  No call graph data found")


def cmd_overview(args):
    """Show binary overview and dump stats."""
    seg_file = FILES['segments']
    if seg_file.exists():
        print("=== SEGMENTS ===")
        with open(seg_file, 'r', encoding='utf-8', errors='ignore') as f:
            print(f.read())

    print("\n=== DUMP FILE STATS ===")
    for name, filepath in sorted(FILES.items()):
        if filepath.exists():
            line_count = 0
            size = filepath.stat().st_size
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for _ in f:
                    line_count += 1
            print(f"  {name:<15} {line_count:>10,} lines  ({size:>14,} bytes)  {filepath.name}")
        else:
            print(f"  {name:<15} {'(not dumped)':>10}")


def cmd_types(args):
    """Search structures/types."""
    pattern = args.pattern
    print(f"Searching types/structures for: '{pattern}'")
    print()

    struct_file = FILES['structures']
    if not struct_file.exists():
        print("  ALL_STRUCTURES.txt not found. Run DumpToolkit first.")
        return

    results = search_file(struct_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_datavars(args):
    """Search data variables / globals in names file."""
    pattern = args.pattern
    print(f"Searching data variables / names for: '{pattern}'")
    print()

    names_file = FILES['names']
    if not names_file.exists():
        print("  ALL_NAMES.txt not found. Run DumpToolkit first.")
        return

    results = search_file(names_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_funcdetail(args):
    """Detailed function info."""
    address = normalize_address(args.address)
    print(f"Function detail for sub_{address}...")
    print()

    # ASM analysis
    asm = extract_function_asm(address)
    if asm:
        asm_lines = asm.splitlines()
        print(f"  Assembly: {len(asm_lines)} lines")

        instr_count = sum(1 for l in asm_lines if re.match(r'\s*\.text:', l))
        print(f"  Instructions: ~{instr_count}")

        # ALL string/data refs
        str_refs = re.findall(r'asc_[0-9A-Fa-f]+|off_[0-9A-Fa-f]+|str_[0-9A-Fa-f]+', asm)
        if str_refs:
            print(f"  String/data refs ({len(str_refs)}):")
            for sr in str_refs:
                print(f"    {sr}")

        # ALL call targets
        calls = re.findall(r'call\s+(\S+)', asm, re.IGNORECASE)
        if calls:
            seen_calls = []
            seen_set = set()
            for c in calls:
                if c not in seen_set:
                    seen_set.add(c)
                    seen_calls.append(c)
            print(f"  Calls ({len(seen_calls)}):")
            for c in seen_calls:
                print(f"    {c}")
    else:
        print(f"  Assembly not found for sub_{address}")

    # Decompiled analysis
    c = extract_function_c(address)
    if c:
        c_lines = c.splitlines()
        print(f"  Decompiled: {len(c_lines)} lines")

        # ALL local variables
        locals_found = []
        for ln in c_lines:
            stripped = ln.strip()
            if stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
                var_match = re.match(r'^\s+(\w[\w\s\*]+\s+\w+)\s*[;=]', ln)
                if var_match:
                    locals_found.append(var_match.group(1).strip())
        if locals_found:
            print(f"  Local variables ({len(locals_found)}):")
            for lv in locals_found:
                print(f"    {lv}")

    # ALL callers/callees
    callers = find_callers(address)
    callees = find_callees(address)
    print(f"  Callers: {len(callers)}")
    for c in callers:
        print(f"    sub_{c['address']}")
    print(f"  Callees: {len(callees)}")
    for c in callees:
        print(f"    sub_{c['address']}")


def cmd_comments(args):
    """Search comments in asm/decompiled."""
    pattern = args.pattern
    print(f"Searching comments for: '{pattern}'")
    print()

    found = False
    c_file = FILES['c']
    if c_file.exists():
        results = search_file(c_file, pattern, is_regex=True, max_results=args.max or 0)
        if results:
            found = True
            print(f"  Decompiled ({len(results)} matches):")
            for r in results:
                print(f"    L{r['line_num']:>8}: {r['line']}")

    asm_file = FILES['asm']
    if asm_file.exists():
        results = search_file(asm_file, pattern, is_regex=True, max_results=args.max or 0)
        if results:
            found = True
            print(f"\n  Assembly ({len(results)} matches):")
            for r in results:
                print(f"    L{r['line_num']:>8}: {r['line']}")

    if not found:
        print("  No matches found")


def cmd_imports(args):
    """Search imports."""
    pattern = args.pattern
    print(f"Searching imports for: '{pattern}'")
    print()

    imp_file = FILES['imports']
    if not imp_file.exists():
        print("  ALL_IMPORTS.txt not found. Run DumpToolkit first.")
        return

    results = search_file(imp_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_exports(args):
    """Search exports."""
    pattern = args.pattern
    print(f"Searching exports for: '{pattern}'")
    print()

    exp_file = FILES['exports']
    if not exp_file.exists():
        print("  ALL_EXPORTS.txt not found. Run DumpToolkit first.")
        return

    results = search_file(exp_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_segments(args):
    """Show all segments."""
    seg_file = FILES['segments']
    if not seg_file.exists():
        print("  ALL_SEGMENTS.txt not found. Run DumpToolkit first.")
        return

    with open(seg_file, 'r', encoding='utf-8', errors='ignore') as f:
        print(f.read())


def cmd_vtables(args):
    """Search vtables."""
    pattern = args.pattern
    print(f"Searching vtables for: '{pattern}'")
    print()

    vt_file = FILES['vtables']
    if not vt_file.exists():
        print("  ALL_VTABLES.txt not found. Run DumpToolkit first.")
        return

    results = search_file(vt_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_rtti(args):
    """Search RTTI / class info."""
    pattern = args.pattern
    print(f"Searching RTTI for: '{pattern}'")
    print()

    rtti_file = FILES['rtti']
    if not rtti_file.exists():
        print("  ALL_RTTI.txt not found. Run DumpToolkit first.")
        return

    results = search_file(rtti_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_structures(args):
    """Search structures."""
    pattern = args.pattern
    print(f"Searching structures for: '{pattern}'")
    print()

    struct_file = FILES['structures']
    if not struct_file.exists():
        print("  ALL_STRUCTURES.txt not found. Run DumpToolkit first.")
        return

    results = search_file(struct_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_names(args):
    """Search named addresses."""
    pattern = args.pattern
    print(f"Searching names for: '{pattern}'")
    print()

    names_file = FILES['names']
    if not names_file.exists():
        print("  ALL_NAMES.txt not found. Run DumpToolkit first.")
        return

    results = search_file(names_file, pattern, is_regex=True, max_results=args.max or 0)
    if results:
        print(f"Found {len(results)} matches:")
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_read(args):
    """Read line range from file."""
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        print(f"Known files: {', '.join(sorted(FILES.keys()))}")
        print(f"Aliases: {', '.join(sorted(FILE_ALIASES.keys()))}")
        return

    start = int(args.start)
    end = int(args.end)

    print(f"Reading {filepath.name} lines {start}-{end}:")
    print()

    lines = read_lines(filepath, start, end)
    for line in lines:
        print(line)


def cmd_grep(args):
    """Grep pattern in file. NO LIMIT."""
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        print(f"Known files: {', '.join(sorted(FILES.keys()))}")
        print(f"Aliases: {', '.join(sorted(FILE_ALIASES.keys()))}")
        return

    pattern = args.pattern
    limit = args.max or 0
    print(f"Grep '{pattern}' in {filepath.name}:")
    print()

    results = search_file(filepath, pattern, is_regex=True, max_results=limit)

    print(f"Found {len(results)} matches:")
    for r in results:
        print(f"  L{r['line_num']:>8}: {r['line']}")


def cmd_around(args):
    """Read lines around a line number."""
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        print(f"Known files: {', '.join(sorted(FILES.keys()))}")
        print(f"Aliases: {', '.join(sorted(FILE_ALIASES.keys()))}")
        return

    line_num = int(args.line)
    context = int(args.context) if args.context else 30

    start = max(1, line_num - context)
    end = line_num + context

    print(f"Reading {filepath.name} around line {line_num} (±{context}):")
    print()

    lines = read_lines(filepath, start, end)
    for line in lines:
        num = int(line.split(':')[0].strip())
        if num == line_num:
            print(f">>> {line}")
        else:
            print(line)


# ============================================================================
# MAIN — 22 commands, all registered
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='IDA Dump Lookup Tool - Search across ALL IDA dump files (ZERO TRUNCATION)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # func
    p = subparsers.add_parser('func', help='Extract function by address (ASM + C + xrefs + callees)')
    p.add_argument('address', help='Function address (e.g., 7FF6FDB8EFA0)')
    p.set_defaults(handler=cmd_func)

    # search
    p = subparsers.add_parser('search', help='Search ALL files')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results per file (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_search)

    # strings
    p = subparsers.add_parser('strings', help='Search strings file')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_strings)

    # strxrefs
    p = subparsers.add_parser('strxrefs', help='Search string cross-references')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_strxrefs)

    # xrefs
    p = subparsers.add_parser('xrefs', help='Find xrefs to address')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_xrefs)

    # callers
    p = subparsers.add_parser('callers', help='Find callers of function')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_callers)

    # callees
    p = subparsers.add_parser('callees', help='Find callees of function')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_callees)

    # callgraph
    p = subparsers.add_parser('callgraph', help='Full call graph for function')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_callgraph)

    # overview
    p = subparsers.add_parser('overview', help='Show binary overview / dump stats')
    p.set_defaults(handler=cmd_overview)

    # types
    p = subparsers.add_parser('types', help='Search structures/types')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_types)

    # datavars
    p = subparsers.add_parser('datavars', help='Search data variables / globals')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_datavars)

    # funcdetail
    p = subparsers.add_parser('funcdetail', help='Detailed function info')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_funcdetail)

    # comments
    p = subparsers.add_parser('comments', help='Search comments in asm/decompiled')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_comments)

    # imports
    p = subparsers.add_parser('imports', help='Search imports')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_imports)

    # exports
    p = subparsers.add_parser('exports', help='Search exports')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_exports)

    # segments
    p = subparsers.add_parser('segments', help='List all segments')
    p.set_defaults(handler=cmd_segments)

    # vtables
    p = subparsers.add_parser('vtables', help='Search vtables')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_vtables)

    # rtti
    p = subparsers.add_parser('rtti', help='Search RTTI / class info')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_rtti)

    # structures
    p = subparsers.add_parser('structures', help='Search structures')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_structures)

    # names
    p = subparsers.add_parser('names', help='Search named addresses')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_names)

    # read
    p = subparsers.add_parser('read', help='Read line range from file')
    p.add_argument('file', help='File name (c, asm, strings, xrefs, imports, exports, etc.)')
    p.add_argument('start', help='Start line')
    p.add_argument('end', help='End line')
    p.set_defaults(handler=cmd_read)

    # grep
    p = subparsers.add_parser('grep', help='Grep pattern in file')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('file', help='File name')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)', default=0)
    p.set_defaults(handler=cmd_grep)

    # around
    p = subparsers.add_parser('around', help='Read lines around a line number')
    p.add_argument('file', help='File name')
    p.add_argument('line', help='Line number')
    p.add_argument('context', nargs='?', help='Context lines (default 30)')
    p.set_defaults(handler=cmd_around)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print("\n\nAvailable dump files:")
        for name, filepath in sorted(FILES.items()):
            status = "✓" if filepath.exists() else "✗"
            print(f"  {status} {name:<15} {filepath.name}")
        print(f"\nAliases: {', '.join(sorted(FILE_ALIASES.keys()))}")
        return

    args.handler(args)


if __name__ == "__main__":
    main()
