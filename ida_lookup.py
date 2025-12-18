#!/usr/bin/env python3
"""
IDA Dump Lookup Tool - Comprehensive search across all IDA dump files.

Usage:
  python ida_lookup.py func <address>              # Extract function (ASM + C)
  python ida_lookup.py search <pattern>            # Search all files for pattern
  python ida_lookup.py strings <pattern>           # Search ALL_STRINGS.txt
  python ida_lookup.py xrefs <address>             # Find all xrefs to/from address
  python ida_lookup.py callers <address>           # Who calls this function?
  python ida_lookup.py callees <address>           # What does this function call?
  python ida_lookup.py read <file> <start> <end>   # Read line range from file
  python ida_lookup.py grep <pattern> <file>       # Grep pattern in specific file
  python ida_lookup.py around <file> <line> [ctx]  # Read lines around a line number

Examples:
  python ida_lookup.py func 7FF6FDB8EFA0
  python ida_lookup.py search "OpenRequest2"
  python ida_lookup.py strings "ChaCha20|AES-GCM"
  python ida_lookup.py xrefs 7FF6FDB71C20
  python ida_lookup.py callers 7FF6FF42BCB0
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

# Configuration
DUMP_DIR = Path(__file__).parent / "DUMP"
OUTPUT_DIR = DUMP_DIR / "extracted"

# File paths
FILES = {
    'asm': DUMP_DIR / "ALL_ASSEMBLY.asm",
    'c': DUMP_DIR / "ALL_DECOMPILED.c",
    'strings': DUMP_DIR / "ALL_STRINGS.txt",
    'xrefs': DUMP_DIR / "ALL_XREFS.txt",
    'names': DUMP_DIR / "ALL_NAMES.txt",
    'vtables': DUMP_DIR / "ALL_VTABLES.txt",
    'rtti': DUMP_DIR / "ALL_RTTI.txt",
}

# Aliases for convenience
FILE_ALIASES = {
    'decompiled': 'c',
    'decompile': 'c',
    'assembly': 'asm',
    'string': 'strings',
    'xref': 'xrefs',
    'name': 'names',
    'vtable': 'vtables',
}


def get_file_path(name: str) -> Path:
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
    """Read specific line range from file (1-indexed)."""
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
                max_results: int = 100, context: int = 0) -> List[Dict]:
    """Search for pattern in file."""
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
            # Keep context buffer
            if context > 0:
                context_buffer.append((line_num, line.rstrip()))
                if len(context_buffer) > context * 2 + 1:
                    context_buffer.pop(0)
            
            # Check match
            if is_regex:
                match = regex.search(line)
            else:
                match = pattern.lower() in line.lower()
            
            if match:
                result = {
                    'line_num': line_num,
                    'line': line.rstrip()[:200],
                    'file': filepath.name
                }
                if context > 0:
                    result['context_before'] = context_buffer[:-1][-context:]
                results.append(result)
                
                if len(results) >= max_results:
                    break
    
    return results


def search_all_files(pattern: str, is_regex: bool = True, max_per_file: int = 30) -> Dict[str, List]:
    """Search pattern across all dump files."""
    all_results = {}
    
    for name, filepath in FILES.items():
        if filepath.exists():
            results = search_file(filepath, pattern, is_regex, max_per_file)
            if results:
                all_results[name] = results
    
    return all_results


def extract_function_asm(address: str) -> Optional[str]:
    """Extract assembly function."""
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
                # End at next function or separator
                if line.upper().startswith("; FUNCTION: SUB_") and f"SUB_{address}" not in line.upper():
                    break
                if line.strip().startswith(";---") and len(lines) > 10:
                    lines.append(line)
                    break
                lines.append(line)
                if len(lines) > 10000:
                    lines.append("\n; === TRUNCATED ===\n")
                    break
    
    return ''.join(lines) if lines else None


def extract_function_c(address: str) -> Optional[str]:
    """Extract decompiled C function."""
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
                # End conditions
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
                if len(lines) > 5000:
                    lines.append("\n// === TRUNCATED ===\n")
                    break
    
    return ''.join(lines) if lines else None


def find_xrefs(address: str) -> Dict[str, List]:
    """Find cross-references to/from an address."""
    addr_upper = address.upper()
    results = {'to': [], 'from': [], 'data': []}
    
    # Search in xrefs file
    xrefs_file = FILES['xrefs']
    if xrefs_file.exists():
        with open(xrefs_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if addr_upper in line.upper():
                    results['data'].append({
                        'line_num': line_num,
                        'line': line.strip()[:200]
                    })
                    if len(results['data']) >= 100:
                        break
    
    # Search for calls in ASM
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
                        'line': line.strip()[:150]
                    })
                    if len(results['to']) >= 50:
                        break
    
    return results


def find_callers(address: str) -> List[Dict]:
    """Find all functions that call this address."""
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
                        'instruction': line.strip()[:100]
                    })
    
    return callers


def find_callees(address: str) -> List[Dict]:
    """Find all functions called by this address."""
    # First extract the function
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
                    'instruction': line.strip()[:100]
                })
    
    return callees


def search_strings(pattern: str, max_results: int = 50) -> List[Dict]:
    """Search in ALL_STRINGS.txt."""
    return search_file(FILES['strings'], pattern, is_regex=True, max_results=max_results)


def cmd_func(args):
    """Handle 'func' command."""
    address = normalize_address(args.address)
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    print(f"Extracting function sub_{address}...")
    print()
    
    # Extract ASM
    asm = extract_function_asm(address)
    if asm:
        out_file = OUTPUT_DIR / f"sub_{address}.asm"
        out_file.write_text(asm, encoding='utf-8')
        print(f"✓ ASM: {out_file.name} ({len(asm.splitlines())} lines)")
    else:
        print(f"✗ ASM not found")
    
    # Extract C
    c = extract_function_c(address)
    if c:
        out_file = OUTPUT_DIR / f"sub_{address}.c"
        out_file.write_text(c, encoding='utf-8')
        print(f"✓ C:   {out_file.name} ({len(c.splitlines())} lines)")
        
        # Print the C code directly if it's reasonable size
        if len(c.splitlines()) <= 300:
            print("\n" + "="*80)
            print(c)
            print("="*80)
    else:
        print(f"✗ C not found")
    
    # Show callers
    print(f"\nCallers of sub_{address}:")
    callers = find_callers(address)
    if callers:
        for c in callers[:15]:
            print(f"  sub_{c['address']} (line {c['func_line']})")
        if len(callers) > 15:
            print(f"  ... and {len(callers) - 15} more")
    else:
        print("  None found")


def cmd_search(args):
    """Handle 'search' command."""
    pattern = args.pattern
    print(f"Searching all files for: '{pattern}'")
    print()
    
    results = search_all_files(pattern, is_regex=True, max_per_file=args.max or 30)
    
    for filename, matches in results.items():
        print(f"\n{'='*60}")
        print(f"  {filename.upper()} ({len(matches)} matches)")
        print('='*60)
        for m in matches[:20]:
            print(f"  L{m['line_num']:>8}: {m['line'][:120]}")
        if len(matches) > 20:
            print(f"  ... and {len(matches) - 20} more in this file")


def cmd_strings(args):
    """Handle 'strings' command."""
    pattern = args.pattern
    print(f"Searching strings for: '{pattern}'")
    print()
    
    results = search_strings(pattern, max_results=args.max or 50)
    
    if results:
        for r in results:
            print(f"  L{r['line_num']:>8}: {r['line']}")
    else:
        print("  No matches found")


def cmd_xrefs(args):
    """Handle 'xrefs' command."""
    address = normalize_address(args.address)
    print(f"Finding xrefs for sub_{address}...")
    print()
    
    results = find_xrefs(address)
    
    if results['to']:
        print(f"Called BY ({len(results['to'])} refs):")
        for r in results['to'][:20]:
            print(f"  sub_{r['caller']:16} L{r['line_num']:>8}: {r['line'][:80]}")
    
    if results['data']:
        print(f"\nXREF data ({len(results['data'])} entries):")
        for r in results['data'][:20]:
            print(f"  L{r['line_num']:>8}: {r['line'][:100]}")


def cmd_callers(args):
    """Handle 'callers' command."""
    address = normalize_address(args.address)
    print(f"Finding callers of sub_{address}...")
    print()
    
    callers = find_callers(address)
    
    if callers:
        print(f"Found {len(callers)} callers:")
        for c in callers:
            print(f"  sub_{c['address']} (func line {c['func_line']}, call line {c['call_line']})")
    else:
        print("  No callers found")


def cmd_callees(args):
    """Handle 'callees' command."""
    address = normalize_address(args.address)
    print(f"Finding functions called by sub_{address}...")
    print()
    
    callees = find_callees(address)
    
    if callees:
        print(f"Calls {len(callees)} functions:")
        for c in callees:
            print(f"  sub_{c['address']}")
    else:
        print("  No callees found (or function not found)")


def cmd_read(args):
    """Handle 'read' command."""
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        print(f"Known files: {', '.join(FILES.keys())}")
        return
    
    start = int(args.start)
    end = int(args.end)
    
    print(f"Reading {filepath.name} lines {start}-{end}:")
    print()
    
    lines = read_lines(filepath, start, end)
    for line in lines:
        print(line)


def cmd_grep(args):
    """Handle 'grep' command."""
    filepath = get_file_path(args.file)
    if not filepath:
        print(f"Error: Unknown file '{args.file}'")
        return
    
    pattern = args.pattern
    print(f"Grep '{pattern}' in {filepath.name}:")
    print()
    
    results = search_file(filepath, pattern, is_regex=True, max_results=args.max or 50)
    
    for r in results:
        print(f"  L{r['line_num']:>8}: {r['line']}")


def cmd_around(args):
    """Handle 'around' command."""
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
        # Highlight the target line
        num = int(line.split(':')[0].strip())
        if num == line_num:
            print(f">>> {line}")
        else:
            print(line)


def main():
    parser = argparse.ArgumentParser(
        description='IDA Dump Lookup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # func command
    p_func = subparsers.add_parser('func', help='Extract function by address')
    p_func.add_argument('address', help='Function address (e.g., 7FF6FDB8EFA0)')
    p_func.set_defaults(handler=cmd_func)
    
    # search command
    p_search = subparsers.add_parser('search', help='Search all files')
    p_search.add_argument('pattern', help='Search pattern (regex)')
    p_search.add_argument('--max', type=int, help='Max results per file')
    p_search.set_defaults(handler=cmd_search)
    
    # strings command
    p_strings = subparsers.add_parser('strings', help='Search strings file')
    p_strings.add_argument('pattern', help='Search pattern (regex)')
    p_strings.add_argument('--max', type=int, help='Max results')
    p_strings.set_defaults(handler=cmd_strings)
    
    # xrefs command
    p_xrefs = subparsers.add_parser('xrefs', help='Find xrefs to address')
    p_xrefs.add_argument('address', help='Function address')
    p_xrefs.set_defaults(handler=cmd_xrefs)
    
    # callers command
    p_callers = subparsers.add_parser('callers', help='Find callers of function')
    p_callers.add_argument('address', help='Function address')
    p_callers.set_defaults(handler=cmd_callers)
    
    # callees command
    p_callees = subparsers.add_parser('callees', help='Find callees of function')
    p_callees.add_argument('address', help='Function address')
    p_callees.set_defaults(handler=cmd_callees)
    
    # read command
    p_read = subparsers.add_parser('read', help='Read line range from file')
    p_read.add_argument('file', help='File name (c, asm, strings, xrefs, etc.)')
    p_read.add_argument('start', help='Start line')
    p_read.add_argument('end', help='End line')
    p_read.set_defaults(handler=cmd_read)
    
    # grep command
    p_grep = subparsers.add_parser('grep', help='Grep pattern in file')
    p_grep.add_argument('pattern', help='Search pattern (regex)')
    p_grep.add_argument('file', help='File name')
    p_grep.add_argument('--max', type=int, help='Max results')
    p_grep.set_defaults(handler=cmd_grep)
    
    # around command
    p_around = subparsers.add_parser('around', help='Read lines around a line number')
    p_around.add_argument('file', help='File name')
    p_around.add_argument('line', help='Line number')
    p_around.add_argument('context', nargs='?', help='Context lines (default 30)')
    p_around.set_defaults(handler=cmd_around)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    args.handler(args)


if __name__ == "__main__":
    main()
