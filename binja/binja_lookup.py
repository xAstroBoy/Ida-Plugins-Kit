#!/usr/bin/env python3
"""
Binary Ninja Dump Lookup Tool — Search and analyze dumps from BinjaDumpToolkit.
ZERO TRUNCATION — every result, every line, every string shown in FULL.

Usage:
  python binja_lookup.py func <address>              # Extract function (ASM + C + IL)
  python binja_lookup.py search <pattern>            # Search all files for pattern
  python binja_lookup.py strings <pattern>           # Search ALL_STRINGS.txt
  python binja_lookup.py strxrefs <pattern>          # Search string→function xref map
  python binja_lookup.py xrefs <address>             # Find all xrefs to/from address
  python binja_lookup.py callers <address>           # Who calls this function?
  python binja_lookup.py callees <address>           # What does this function call?
  python binja_lookup.py callgraph <address>         # Show full call graph for function
  python binja_lookup.py overview                    # Show binary overview/triage info
  python binja_lookup.py types <pattern>             # Search type library
  python binja_lookup.py datavars <pattern>          # Search data variables
  python binja_lookup.py funcdetail <address>        # Show rich function details
  python binja_lookup.py il <address>                # Show IL pipeline for function
  python binja_lookup.py comments <pattern>          # Search comments/tags
  python binja_lookup.py imports <pattern>           # Search imports
  python binja_lookup.py exports <pattern>           # Search exports
  python binja_lookup.py segments                    # Show segment map
  python binja_lookup.py vtables <pattern>           # Search vtables
  python binja_lookup.py rtti <pattern>              # Search RTTI info
  python binja_lookup.py structures <pattern>        # Search structures
  python binja_lookup.py names <pattern>             # Search names/symbols
  python binja_lookup.py read <file> <start> <end>   # Read line range from file
  python binja_lookup.py grep <pattern> <file>       # Grep pattern in specific file
  python binja_lookup.py around <file> <line> [ctx]  # Read lines around a line number

Examples:
  python binja_lookup.py func 7FF6FDB8EFA0
  python binja_lookup.py search "OpenRequest2"
  python binja_lookup.py strings "ChaCha20|AES-GCM"
  python binja_lookup.py strxrefs "password"
  python binja_lookup.py xrefs 7FF6FDB71C20
  python binja_lookup.py callers 7FF6FF42BCB0
  python binja_lookup.py callgraph 7FF6FDB8EFA0
  python binja_lookup.py overview
  python binja_lookup.py types "SOCKET|sockaddr"
  python binja_lookup.py datavars "g_config"
  python binja_lookup.py funcdetail 7FF6FDB8EFA0
  python binja_lookup.py il 7FF6FDB8EFA0
  python binja_lookup.py comments "TODO|fixme"
  python binja_lookup.py imports "ssl|crypto"
  python binja_lookup.py exports "main|init"
  python binja_lookup.py segments
  python binja_lookup.py vtables "vtable"
  python binja_lookup.py rtti "class"
  python binja_lookup.py structures "sockaddr"
  python binja_lookup.py names "sub_|data_"
  python binja_lookup.py read ALL_DECOMPILED.c 6676900 6677100
  python binja_lookup.py grep "case 0x78" ALL_DECOMPILED.c
  python binja_lookup.py around ALL_DECOMPILED.c 6676949 50
"""

import sys
import re
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import argparse

# Configuration — point at BINJA_DUMPS directory
DUMP_DIR = Path(__file__).parent / "DUMP"
OUTPUT_DIR = DUMP_DIR / "extracted"

# File paths
FILES = {
    'asm': DUMP_DIR / "ALL_ASSEMBLY.asm",
    'c': DUMP_DIR / "ALL_DECOMPILED.c",
    'strings': DUMP_DIR / "ALL_STRINGS.txt",
    'strxrefs': DUMP_DIR / "ALL_STRING_XREFS.txt",
    'xrefs': DUMP_DIR / "ALL_XREFS.txt",
    'names': DUMP_DIR / "ALL_NAMES.txt",
    'vtables': DUMP_DIR / "ALL_VTABLES.txt",
    'rtti': DUMP_DIR / "ALL_RTTI.txt",
    'segments': DUMP_DIR / "ALL_SEGMENTS.txt",
    'imports': DUMP_DIR / "ALL_IMPORTS.txt",
    'exports': DUMP_DIR / "ALL_EXPORTS.txt",
    'structures': DUMP_DIR / "ALL_STRUCTURES.txt",
    'types': DUMP_DIR / "ALL_TYPES.txt",
    'overview': DUMP_DIR / "ALL_OVERVIEW.txt",
    'datavars': DUMP_DIR / "ALL_DATA_VARIABLES.txt",
    'callgraph': DUMP_DIR / "ALL_CALL_GRAPH.txt",
    'funcdetails': DUMP_DIR / "ALL_FUNCTIONS_DETAIL.txt",
    'comments': DUMP_DIR / "ALL_COMMENTS_TAGS.txt",
    'il': DUMP_DIR / "ALL_IL_PIPELINE.txt",
}

# Aliases for convenience
FILE_ALIASES = {
    'decompiled': 'c',
    'decompile': 'c',
    'assembly': 'asm',
    'string': 'strings',
    'string_xrefs': 'strxrefs',
    'stringxrefs': 'strxrefs',
    'xref': 'xrefs',
    'name': 'names',
    'vtable': 'vtables',
    'segment': 'segments',
    'import': 'imports',
    'export': 'exports',
    'struct': 'structures',
    'structure': 'structures',
    'type': 'types',
    'typedef': 'types',
    'data_variables': 'datavars',
    'data_vars': 'datavars',
    'vars': 'datavars',
    'call_graph': 'callgraph',
    'graph': 'callgraph',
    'func_details': 'funcdetails',
    'functions': 'funcdetails',
    'func_detail': 'funcdetails',
    'comment': 'comments',
    'tags': 'comments',
    'tag': 'comments',
    'il_pipeline': 'il',
    'pipeline': 'il',
    'llil': 'il',
    'mlil': 'il',
    'hlil': 'il',
    'triage': 'overview',
    'info': 'overview',
}


def get_file_path(name: str) -> Optional[Path]:
    """Get file path from name or alias."""
    name_lower = name.lower()

    # Check aliases
    if name_lower in FILE_ALIASES:
        name_lower = FILE_ALIASES[name_lower]

    # Check known files
    if name_lower in FILES:
        return FILES[name_lower]

    # Check if it's a direct filename
    direct = DUMP_DIR / name
    if direct.exists():
        return direct

    # Try with .txt extension
    txt = DUMP_DIR / f"{name}.txt"
    if txt.exists():
        return txt

    return None


def normalize_address(addr: str) -> str:
    """Normalize address to uppercase hex."""
    addr = addr.upper().strip()
    for prefix in ['SUB_', '0X', 'LOC_']:
        if addr.startswith(prefix):
            addr = addr[len(prefix):]
    return addr


def read_lines(filepath: Path, start: int, end: int) -> List[str]:
    """Read specific line range from file (1-indexed). NO LIMIT."""
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


# ============================================================================
# CORE SEARCH — ZERO TRUNCATION
# ============================================================================

def search_file(filepath: Path, pattern: str, is_regex: bool = True,
                max_results: int = 0, context: int = 0) -> List[Dict]:
    """Search for pattern in file. max_results=0 means UNLIMITED. FULL lines returned."""
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
    """Extract assembly function by address. COMPLETE — no line limit."""
    filepath = FILES['asm']
    if not filepath.exists():
        return None

    lines = []
    in_function = False
    addr_upper = address.upper()

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if not in_function:
                if f"; Function:" in line and addr_upper in line.upper():
                    in_function = True
                    lines.append(f"; === Line {line_num} ===\n")
                    lines.append(line)
                elif f"sub_{addr_upper}" in line.upper() and "; Function:" in line:
                    in_function = True
                    lines.append(f"; === Line {line_num} ===\n")
                    lines.append(line)
            else:
                if line.strip().startswith("; Function:") and addr_upper not in line.upper():
                    break
                if line.strip().startswith(";---") and len(lines) > 10:
                    lines.append(line)
                    break
                lines.append(line)

    return ''.join(lines) if lines else None


def extract_function_c(address: str) -> Optional[str]:
    """Extract decompiled C function by address. COMPLETE — no line limit."""
    filepath = FILES['c']
    if not filepath.exists():
        return None

    lines = []
    in_function = False
    brace_count = 0
    found_body = False
    addr_upper = address.upper()
    separator = "/------------------------------------------------------------------------------/"

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if not in_function:
                if f"// Address: 0x{addr_upper}" in line.upper() or f"// Address: 0X{addr_upper}" in line.upper():
                    in_function = True
                    lines.append(f"// === Line {line_num} ===\n")
                    lines.append(line)
                elif f"sub_{addr_upper}" in line.upper() and "// Function:" in line:
                    in_function = True
                    lines.append(f"// === Line {line_num} ===\n")
                    lines.append(line)
            else:
                if separator in line and found_body and brace_count <= 0:
                    break
                if "// Function:" in line and addr_upper not in line.upper():
                    if found_body and brace_count <= 0:
                        break

                lines.append(line)
                brace_count += line.count('{') - line.count('}')
                if '{' in line:
                    found_body = True

                if found_body and brace_count <= 0 and len(lines) > 5:
                    break

    return ''.join(lines) if lines else None


def extract_function_il(address: str) -> Optional[str]:
    """Extract IL pipeline for a function. COMPLETE — no line limit."""
    filepath = FILES.get('il')
    if not filepath or not filepath.exists():
        return None

    addr_upper = address.upper()
    in_func = False
    lines = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if f"// Address: 0x{addr_upper}" in line.upper() or f"// Address: 0X{addr_upper}" in line.upper():
                in_func = True
                lines.append(line.rstrip())
            elif in_func:
                if line.startswith("/---") and len(lines) > 5:
                    break
                lines.append(line.rstrip())

    return '\n'.join(lines) if lines else None


def find_xrefs(address: str) -> Dict[str, List]:
    """Find cross-references to/from an address. ALL results, FULL lines."""
    addr_upper = address.upper()
    results = {'to': [], 'from': [], 'data': []}

    xrefs_file = FILES['xrefs']
    if xrefs_file.exists():
        with open(xrefs_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if addr_upper in line.upper():
                    results['data'].append({
                        'line_num': line_num,
                        'line': line.strip()  # FULL LINE
                    })

    # Search for calls in ASM — FULL lines
    asm_file = FILES['asm']
    if asm_file.exists():
        call_pattern = re.compile(rf'(call|jmp|bl|blr)\s+.*{addr_upper}', re.IGNORECASE)
        current_func = "unknown"

        with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if "; Function:" in line:
                    match = re.search(r'(?:sub_)?([0-9A-Fa-f]+)', line, re.IGNORECASE)
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
    """Find all functions that call this address. ALL callers, FULL instructions."""
    addr_upper = address.upper()
    callers = []
    seen = set()

    asm_file = FILES['asm']
    if not asm_file.exists():
        # Try xrefs file as fallback
        xrefs_file = FILES['xrefs']
        if xrefs_file.exists():
            in_target = False
            with open(xrefs_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if f"[FUNC]" in line and addr_upper in line.upper():
                        in_target = True
                    elif "[FUNC]" in line:
                        in_target = False
                    elif in_target and "Called by" in line:
                        continue
                    elif in_target and line.strip().startswith("0") and addr_upper not in line.upper():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            callers.append({
                                'address': parts[0],
                                'func_line': line_num,
                                'call_line': line_num,
                                'instruction': ' '.join(parts[1:])  # FULL — no truncation
                            })
        return callers

    current_func = None
    func_line = 0
    pattern = re.compile(rf'(call|bl|blr)\s+.*{addr_upper}', re.IGNORECASE)

    with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if "; Function:" in line:
                match = re.search(r'(?:sub_)?([0-9A-Fa-f]+)', line, re.IGNORECASE)
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
    """Find all functions called by this address. ALL callees, FULL instructions."""
    asm_content = extract_function_asm(address)
    if not asm_content:
        return []

    callees = []
    seen = set()
    pattern = re.compile(r'(?:call|bl|blr)\s+(?:sub_)?([0-9A-Fa-f]+)', re.IGNORECASE)

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


def extract_block(filepath: Path, address: str, start_marker: str = "[FUNC]",
                  end_markers: List[str] = None) -> Optional[str]:
    """Generic block extractor — finds a section by address and returns ALL of it."""
    if not filepath or not filepath.exists():
        return None

    if end_markers is None:
        end_markers = [start_marker, "/---"]

    addr_upper = address.upper()
    in_block = False
    lines = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if not in_block:
                if addr_upper in line.upper() and start_marker in line:
                    in_block = True
                    lines.append(line.rstrip())
            else:
                # Check if we hit a new block
                hit_end = False
                for marker in end_markers:
                    if marker in line and addr_upper not in line.upper() and len(lines) > 3:
                        hit_end = True
                        break
                if hit_end:
                    break
                lines.append(line.rstrip())

    return '\n'.join(lines) if lines else None


# ============================================================================
# CLI COMMANDS — ALL OUTPUT FULL, ZERO TRUNCATION
# ============================================================================

def cmd_func(args):
    address = normalize_address(args.address)
    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"Extracting function at 0x{address}...")
    print()

    asm = extract_function_asm(address)
    if asm:
        out_file = OUTPUT_DIR / f"sub_{address}.asm"
        out_file.write_text(asm, encoding='utf-8')
        print(f"✓ ASM: {out_file.name} ({len(asm.splitlines())} lines)")
    else:
        print("✗ ASM not found")

    c = extract_function_c(address)
    if c:
        out_file = OUTPUT_DIR / f"sub_{address}.c"
        out_file.write_text(c, encoding='utf-8')
        print(f"✓ C:   {out_file.name} ({len(c.splitlines())} lines)")

        print("\n" + "=" * 80)
        print(c)
        print("=" * 80)
    else:
        print("✗ C not found")

    # Also extract IL pipeline if available
    il = extract_function_il(address)
    if il:
        out_file = OUTPUT_DIR / f"sub_{address}_il.txt"
        out_file.write_text(il, encoding='utf-8')
        print(f"✓ IL Pipeline: {out_file.name} ({len(il.splitlines())} lines)")
    else:
        print("✗ IL Pipeline not found")

    # Also extract function details if available
    detail = extract_block(FILES.get('funcdetails'), address, "[FUNC]")
    if detail:
        out_file = OUTPUT_DIR / f"sub_{address}_detail.txt"
        out_file.write_text(detail, encoding='utf-8')
        print(f"✓ Function details: {out_file.name} ({len(detail.splitlines())} lines)")

    # Callers — ALL of them
    print(f"\nCallers of 0x{address}:")
    callers = find_callers(address)
    if callers:
        print(f"Found {len(callers)} callers:")
        for c in callers:
            print(f"  {c['address']} (line {c['func_line']})")
    else:
        print("  None found")

    # Callees — ALL of them
    print(f"\nCallees of 0x{address}:")
    callees = find_callees(address)
    if callees:
        print(f"Calls {len(callees)} functions:")
        for c in callees:
            print(f"  {c['address']}: {c['instruction']}")
    else:
        print("  None found")


def cmd_search(args):
    pattern = args.pattern
    print(f"Searching all files for: '{pattern}'")
    print()

    limit = args.max if args.max else 0
    results = search_all_files(pattern, is_regex=True, max_per_file=limit)

    total_matches = 0
    for filename, matches in results.items():
        total_matches += len(matches)
        print(f"\n{'=' * 60}")
        print(f"  {filename.upper()} ({len(matches)} matches)")
        print('=' * 60)
        for m in matches:
            print(f"  L{m['line_num']:>8}: {m['line']}")  # FULL LINE

    print(f"\nTotal: {total_matches} matches across {len(results)} files")


def cmd_strings(args):
    pattern = args.pattern
    print(f"Searching strings for: '{pattern}'")
    print()

    limit = args.max if args.max else 0
    results = search_strings(pattern, max_results=limit)

    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")  # FULL LINE
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_xrefs(args):
    address = normalize_address(args.address)
    print(f"Finding xrefs for 0x{address}...")
    print()

    results = find_xrefs(address)

    if results['to']:
        print(f"Called BY ({len(results['to'])} refs):")
        for r in results['to']:  # ALL — no slicing
            print(f"  {r['caller']:16} L{r['line_num']:>8}: {r['line']}")  # FULL LINE

    if results['data']:
        print(f"\nXREF data ({len(results['data'])} entries):")
        for r in results['data']:  # ALL — no slicing
            print(f"  L{r['line_num']:>8}: {r['line']}")  # FULL LINE


def cmd_callers(args):
    address = normalize_address(args.address)
    print(f"Finding callers of 0x{address}...")
    print()

    callers = find_callers(address)

    if callers:
        print(f"Found {len(callers)} callers:")
        for c in callers:  # ALL
            print(f"  {c['address']} (func line {c['func_line']}, call line {c['call_line']})")
            print(f"    {c['instruction']}")  # FULL INSTRUCTION
    else:
        print("  No callers found")


def cmd_callees(args):
    address = normalize_address(args.address)
    print(f"Finding functions called by 0x{address}...")
    print()

    callees = find_callees(address)

    if callees:
        print(f"Calls {len(callees)} functions:")
        for c in callees:  # ALL
            print(f"  {c['address']}: {c['instruction']}")  # FULL INSTRUCTION
    else:
        print("  No callees found (or function not found)")


def cmd_read(args):
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        print(f"Known files: {', '.join(sorted(FILES.keys()))}")
        return

    start = int(args.start)
    end = int(args.end)

    print(f"Reading {filepath.name} lines {start}-{end}:")
    print()

    lines = read_lines(filepath, start, end)
    for line in lines:
        print(line)


def cmd_grep(args):
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        return

    pattern = args.pattern
    limit = args.max if args.max else 0
    print(f"Grep '{pattern}' in {filepath.name}:")
    print()

    results = search_file(filepath, pattern, is_regex=True, max_results=limit)

    for r in results:
        print(f"  L{r['line_num']:>8}: {r['line']}")  # FULL LINE
    print(f"\n  Total: {len(results)} matches")


def cmd_around(args):
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
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


def cmd_strxrefs(args):
    """Search the string→function cross-reference map. ALL results."""
    pattern = args.pattern
    print(f"Searching string xrefs for: '{pattern}'")
    print()

    filepath = FILES.get('strxrefs')
    if not filepath or not filepath.exists():
        print("Error: ALL_STRING_XREFS.txt not found. Run the String Xrefs dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")  # FULL LINE
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_overview(args):
    """Show the binary overview/triage information. FULL output."""
    filepath = FILES.get('overview')
    if not filepath or not filepath.exists():
        print("Error: ALL_OVERVIEW.txt not found. Run the Overview dump first.")
        return

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        print(f.read())


def cmd_types(args):
    """Search the full type library. ALL results."""
    pattern = args.pattern
    print(f"Searching types for: '{pattern}'")
    print()

    filepath = FILES.get('types')
    if not filepath or not filepath.exists():
        filepath = FILES.get('structures')
    if not filepath or not filepath.exists():
        print("Error: ALL_TYPES.txt not found. Run the Types dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_datavars(args):
    """Search data variables. ALL results."""
    pattern = args.pattern
    print(f"Searching data variables for: '{pattern}'")
    print()

    filepath = FILES.get('datavars')
    if not filepath or not filepath.exists():
        print("Error: ALL_DATA_VARIABLES.txt not found. Run the Data Variables dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_funcdetail(args):
    """Show rich function details by address. COMPLETE block."""
    address = normalize_address(args.address)
    print(f"Finding function details for 0x{address}...")
    print()

    filepath = FILES.get('funcdetails')
    if not filepath or not filepath.exists():
        print("Error: ALL_FUNCTIONS_DETAIL.txt not found. Run the Function Details dump first.")
        return

    # Find the function block — dump EVERYTHING until next [FUNC]
    in_func = False
    lines = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if f"[FUNC]" in line and address.upper() in line.upper():
                in_func = True
                lines.append(line.rstrip())
            elif in_func:
                if line.startswith("/") or (line.startswith("[FUNC]") and address.upper() not in line.upper()):
                    break
                lines.append(line.rstrip())

    if lines:
        for l in lines:
            print(l)
    else:
        print(f"  Function 0x{address} not found in details dump")


def cmd_il(args):
    """Show IL pipeline (LLIL→MLIL→HLIL) for a function. COMPLETE — ZERO TRUNCATION."""
    address = normalize_address(args.address)
    print(f"Finding IL pipeline for 0x{address}...")
    print()

    il = extract_function_il(address)
    if il:
        print(il)
    else:
        print(f"  IL pipeline for 0x{address} not found")


def cmd_callgraph(args):
    """Show call graph (callers + callees) for a function. ALL entries."""
    address = normalize_address(args.address)
    print(f"Call graph for 0x{address}:")
    print()

    filepath = FILES.get('callgraph')
    if filepath and filepath.exists():
        # Search the call graph file — ALL results
        results = search_file(filepath, address, is_regex=False, max_results=0)
        if results:
            print(f"Found {len(results)} edges:")
            for r in results:
                print(f"  {r['line']}")  # FULL LINE
        else:
            print("  Not found in call graph")
    else:
        # Fallback to callers/callees — ALL of them
        print("[CALLERS]")
        callers = find_callers(address)
        if callers:
            for c in callers:  # ALL
                print(f"  ← {c['address']}: {c['instruction']}")
        else:
            print("  None")

        print("\n[CALLEES]")
        callees = find_callees(address)
        if callees:
            for c in callees:  # ALL
                print(f"  → {c['address']}: {c['instruction']}")
        else:
            print("  None")


def cmd_comments(args):
    """Search comments and tags. ALL results."""
    pattern = args.pattern
    print(f"Searching comments/tags for: '{pattern}'")
    print()

    filepath = FILES.get('comments')
    if not filepath or not filepath.exists():
        print("Error: ALL_COMMENTS_TAGS.txt not found. Run the Comments & Tags dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_imports(args):
    """Search imports. ALL results."""
    pattern = args.pattern
    print(f"Searching imports for: '{pattern}'")
    print()

    filepath = FILES.get('imports')
    if not filepath or not filepath.exists():
        print("Error: ALL_IMPORTS.txt not found. Run the Imports dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_exports(args):
    """Search exports. ALL results."""
    pattern = args.pattern
    print(f"Searching exports for: '{pattern}'")
    print()

    filepath = FILES.get('exports')
    if not filepath or not filepath.exists():
        print("Error: ALL_EXPORTS.txt not found. Run the Exports dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_segments(args):
    """Show segment map. FULL output."""
    filepath = FILES.get('segments')
    if not filepath or not filepath.exists():
        print("Error: ALL_SEGMENTS.txt not found. Run the Segments dump first.")
        return

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        print(f.read())


def cmd_vtables(args):
    """Search vtables. ALL results."""
    pattern = args.pattern
    print(f"Searching vtables for: '{pattern}'")
    print()

    filepath = FILES.get('vtables')
    if not filepath or not filepath.exists():
        print("Error: ALL_VTABLES.txt not found. Run the VTables dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_rtti(args):
    """Search RTTI info. ALL results."""
    pattern = args.pattern
    print(f"Searching RTTI for: '{pattern}'")
    print()

    filepath = FILES.get('rtti')
    if not filepath or not filepath.exists():
        print("Error: ALL_RTTI.txt not found. Run the RTTI dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_structures(args):
    """Search structures. ALL results."""
    pattern = args.pattern
    print(f"Searching structures for: '{pattern}'")
    print()

    filepath = FILES.get('structures')
    if not filepath or not filepath.exists():
        print("Error: ALL_STRUCTURES.txt not found. Run the Structures dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


def cmd_names(args):
    """Search names/symbols. ALL results."""
    pattern = args.pattern
    print(f"Searching names for: '{pattern}'")
    print()

    filepath = FILES.get('names')
    if not filepath or not filepath.exists():
        print("Error: ALL_NAMES.txt not found. Run the Names dump first.")
        return

    limit = args.max if args.max else 0
    results = search_file(filepath, pattern, is_regex=True, max_results=limit)
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
        print(f"\n  Total: {len(results)} matches")
    else:
        print("  No matches found")


# ============================================================================
# MAIN — ARGPARSE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Binary Ninja Dump Lookup Tool — ZERO TRUNCATION',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # func
    p = subparsers.add_parser('func', help='Extract function by address')
    p.add_argument('address', help='Function address (e.g., 7FF6FDB8EFA0)')
    p.set_defaults(handler=cmd_func)

    # search
    p = subparsers.add_parser('search', help='Search all files')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results per file (0=unlimited)')
    p.set_defaults(handler=cmd_search)

    # strings
    p = subparsers.add_parser('strings', help='Search strings file')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_strings)

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

    # read
    p = subparsers.add_parser('read', help='Read line range from file')
    p.add_argument('file', help='File name (c, asm, strings, xrefs, etc.)')
    p.add_argument('start', help='Start line')
    p.add_argument('end', help='End line')
    p.set_defaults(handler=cmd_read)

    # grep
    p = subparsers.add_parser('grep', help='Grep pattern in file')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('file', help='File name')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_grep)

    # around
    p = subparsers.add_parser('around', help='Read lines around a line number')
    p.add_argument('file', help='File name')
    p.add_argument('line', help='Line number')
    p.add_argument('context', nargs='?', help='Context lines (default 30)')
    p.set_defaults(handler=cmd_around)

    # strxrefs
    p = subparsers.add_parser('strxrefs', help='Search string→function xref map')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_strxrefs)

    # overview
    p = subparsers.add_parser('overview', help='Show binary overview/triage')
    p.set_defaults(handler=cmd_overview)

    # types
    p = subparsers.add_parser('types', help='Search type library')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_types)

    # datavars
    p = subparsers.add_parser('datavars', help='Search data variables')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_datavars)

    # funcdetail
    p = subparsers.add_parser('funcdetail', help='Show rich function details')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_funcdetail)

    # il
    p = subparsers.add_parser('il', help='Show IL pipeline (LLIL→MLIL→HLIL)')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_il)

    # callgraph
    p = subparsers.add_parser('callgraph', help='Show call graph for function')
    p.add_argument('address', help='Function address')
    p.set_defaults(handler=cmd_callgraph)

    # comments
    p = subparsers.add_parser('comments', help='Search comments and tags')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_comments)

    # imports
    p = subparsers.add_parser('imports', help='Search imports')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_imports)

    # exports
    p = subparsers.add_parser('exports', help='Search exports')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_exports)

    # segments
    p = subparsers.add_parser('segments', help='Show segment map')
    p.set_defaults(handler=cmd_segments)

    # vtables
    p = subparsers.add_parser('vtables', help='Search vtables')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_vtables)

    # rtti
    p = subparsers.add_parser('rtti', help='Search RTTI info')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_rtti)

    # structures
    p = subparsers.add_parser('structures', help='Search structures')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_structures)

    # names
    p = subparsers.add_parser('names', help='Search names/symbols')
    p.add_argument('pattern', help='Search pattern (regex)')
    p.add_argument('--max', type=int, help='Max results (0=unlimited)')
    p.set_defaults(handler=cmd_names)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.handler(args)


if __name__ == "__main__":
    main()
