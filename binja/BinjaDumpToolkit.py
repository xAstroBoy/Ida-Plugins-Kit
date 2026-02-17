# Binary Ninja Plugin — Dump EVERY GODDAMN THING from the database
# Leverages Binary Ninja's superior IL pipeline for clean deobfuscated output.
#
# What IDA can't do that this does:
#   - LLIL → MLIL → HLIL pipeline dump (shows the full deobfuscation chain)
#   - Linear View decompilation (Binja's cleanest, most type-aware output)
#   - Recovered local variables with inferred types per function
#   - Full data variable dump with types and initial values
#   - String→function xref map (which functions touch which strings)
#   - Complete call graph with edge types
#   - Every comment, tag, and bookmark in the database
#   - Full type library (typedefs, function pointers, arrays — not just structs)
#   - Binary overview/triage metadata
#
# Install: Copy to Binary Ninja plugins folder.
#   Windows: %APPDATA%\Binary Ninja\plugins\
#   Linux:   ~/.binaryninja/plugins/
#   macOS:   ~/Library/Application Support/Binary Ninja/plugins/
from __future__ import print_function

import os
import re
import hashlib
import traceback
import time
import json
from typing import Optional, List, Dict, Tuple, Set

import binaryninja as bn
from binaryninja import (
    BinaryView,
    Function,
    Symbol,
    SymbolType,
    PluginCommand,
    BackgroundTaskThread,
    log_info,
    log_warn,
    log_error,
    interaction,
)

PLUGIN_NAME = "Binary Ninja Dumper"
OUTPUT_DIR_NAME = "BINJA_DUMPS"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def sanitize_filename(name: str) -> str:
    return re.sub(r'[^0-9A-Za-z._-]', '_', name)


def ensure_output_dir(bv: BinaryView, subdir: str = None) -> str:
    input_path = bv.file.filename or ""
    base_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    outdir = os.path.join(base_dir, OUTPUT_DIR_NAME)
    if subdir:
        outdir = os.path.join(outdir, subdir)
    try:
        os.makedirs(outdir, exist_ok=True)
    except Exception:
        outdir = os.path.join(os.getcwd(), OUTPUT_DIR_NAME)
        if subdir:
            outdir = os.path.join(outdir, subdir)
        os.makedirs(outdir, exist_ok=True)
    return outdir


def func_name(func: Function) -> str:
    name = func.symbol.short_name if func.symbol else None
    if not name:
        name = func.name or f"sub_{func.start:X}"
    return name


def _set_clipboard(text: str) -> None:
    """Copy text to the system clipboard (cross-platform)."""
    import subprocess, sys
    if sys.platform == "win32":
        import ctypes
        k32 = ctypes.windll.kernel32
        u32 = ctypes.windll.user32
        u32.OpenClipboard(0)
        u32.EmptyClipboard()
        data = text.encode("utf-16-le") + b"\x00\x00"
        h = k32.GlobalAlloc(0x0042, len(data))
        p = k32.GlobalLock(h)
        ctypes.memmove(p, data, len(data))
        k32.GlobalUnlock(h)
        u32.SetClipboardData(13, h)  # CF_UNICODETEXT = 13
        u32.CloseClipboard()
    elif sys.platform == "darwin":
        subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=False)
    else:
        try:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode("utf-8"), check=False)
        except FileNotFoundError:
            subprocess.run(["xsel", "--clipboard", "--input"], input=text.encode("utf-8"), check=False)


def _is_64bit(bv: BinaryView) -> bool:
    return bv.address_size == 8


def _addr_w(bv: BinaryView) -> int:
    return 16 if _is_64bit(bv) else 8


def _safe_str(data: bytes) -> str:
    """Decode bytes to string safely."""
    if not data:
        return ""
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return data.decode("latin-1", errors="replace")


def _get_func_string_refs(bv: BinaryView, func: Function) -> list:
    """Get all strings referenced by a function via data refs.
    Uses bv.get_data_refs_from() per address — func.data_refs does NOT exist."""
    seen = set()
    results = []
    for block in func.basic_blocks:
        for addr in range(block.start, block.end):
            for ref in bv.get_data_refs_from(addr):
                if ref in seen:
                    continue
                seen.add(ref)
                s = bv.get_string_at(ref)
                if s:
                    content = bv.read(s.start, s.length)
                    if content:
                        results.append((s.start, _safe_str(content)))
    return results


def _read_ptr(bv: BinaryView, addr: int) -> int:
    """Read a pointer-sized value from the binary."""
    ps = bv.address_size
    data = bv.read(addr, ps)
    if not data or len(data) < ps:
        return 0
    return int.from_bytes(
        data,
        "little" if bv.endianness == bn.Endianness.LittleEndian else "big",
    )


# ============================================================================
# FUNCTION EXTRACTION — Assembly
# ============================================================================

def get_function_assembly(bv: BinaryView, func: Function) -> Optional[str]:
    """Full disassembly listing with comments."""
    lines = []
    name = func_name(func)
    aw = _addr_w(bv)

    lines.append(f"; Function: {name}")
    lines.append(f"; Address: 0x{func.start:X} - 0x{func.highest_address:X}")
    lines.append(f"; Size: {func.total_bytes} bytes")
    lines.append("")

    for block in sorted(func.basic_blocks, key=lambda b: b.start):
        for line in block.get_disassembly_text():
            addr = line.address
            text = "".join(str(tok) for tok in line.tokens)
            entry = f".text:{addr:0{aw}X}    {text}"
            comment = func.get_comment_at(addr)
            if comment:
                entry += f"    ; {comment}"
            lines.append(entry)

    return "\n".join(lines) if lines else None


# ============================================================================
# FUNCTION EXTRACTION — Decompiled (HLIL + Linear View)
# ============================================================================

def _lines_to_text(lines) -> List[str]:
    """Convert DisassemblyTextLine objects to a list of strings.
    Each DisassemblyTextLine has a .tokens list of InstructionTextToken,
    and each token has a .text string.
    """
    result = []
    for line in lines:
        # Handle LinearDisassemblyLine (has .contents → DisassemblyTextLine)
        dtl = getattr(line, 'contents', line)
        tokens = getattr(dtl, 'tokens', None)
        if tokens is not None:
            result.append("".join(t.text for t in tokens))
        else:
            result.append(str(line))
    return result


_decompile_diag_count = 0  # module-level diagnostic counter

def get_function_decompiled(bv: BinaryView, func: Function) -> Optional[str]:
    """Get the HLIL decompiled pseudocode.

    Binary Ninja's HLIL pipeline performs:
      - Dead code elimination
      - Constant folding & propagation
      - Expression simplification
      - Control flow recovery (if/else/while/for from obfuscated jumps)
      - Variable recovery & type inference
      - Copy propagation & dead store elimination
    All of which IDA's Hex-Rays does NOT do as aggressively.

    Tries multiple approaches (v5.2 API):
      1. func.pseudo_c → LanguageRepresentationFunction.get_linear_lines()
      2. LinearViewObject.single_function_language_representation()
      3. hlil.root.lines (structured HLIL tokens)
      4. hlil.instructions (iterate each HLIL instruction)
      5. func.hlil_if_available (non-blocking, maybe cached)
      6. MLIL fallback (still better than raw asm)
    """
    name = func_name(func)
    global _decompile_diag_count
    _strategy_errors = []  # collect per-strategy error info for diagnostics

    # Build function header (used by strategies that don't include their own)
    def _build_header():
        header_lines = []
        try:
            ret_type = func.return_type
            ret_str = str(ret_type) if ret_type else "void"
            params = ", ".join(
                f"{p.type} {p.name}" if p.type else p.name
                for p in func.parameter_vars
            ) or "void"
            calling_conv = func.calling_convention
            cc_str = f" /* {calling_conv.name} */" if calling_conv else ""
            header_lines.append(f"{ret_str}{cc_str} {name}({params})")
        except Exception:
            header_lines.append(f"void {name}(void)")
        header_lines.append("{")

        # Local variable declarations
        try:
            for var in func.vars:
                try:
                    if var.source_type == bn.VariableSourceType.StackVariableSourceType:
                        vtype = str(var.type) if var.type else "int"
                        header_lines.append(f"    {vtype} {var.name};  // stack[{var.storage:#x}]")
                    elif var.source_type == bn.VariableSourceType.RegisterVariableSourceType:
                        vtype = str(var.type) if var.type else "int"
                        header_lines.append(f"    {vtype} {var.name};  // register")
                except Exception:
                    pass
            if len(header_lines) > 2:
                header_lines.append("")
        except Exception:
            pass
        return header_lines

    # Strategy 1: func.pseudo_c → LanguageRepresentationFunction.get_linear_lines()
    # This is the BEST approach — returns clean Pseudo C exactly like the GUI
    try:
        lang_rep = func.pseudo_c
        if lang_rep is not None:
            hlil = lang_rep.hlil if hasattr(lang_rep, 'hlil') else func.hlil
            if hlil is not None and hlil.root is not None:
                dtl_lines = lang_rep.get_linear_lines(hlil.root)
                text_lines = _lines_to_text(dtl_lines)
                if text_lines:
                    return "\n".join(text_lines)
    except Exception as e:
        _strategy_errors.append(f"S1_pseudo_c: {type(e).__name__}: {e}")

    # Strategy 2: single_function_language_representation (Linear View per-function)
    try:
        linear = get_function_decompiled_linear(bv, func)
        if linear:
            return linear
    except Exception as e:
        _strategy_errors.append(f"S2_linear: {type(e).__name__}: {e}")

    # Strategy 3: hlil.root.lines (token-based extraction)
    try:
        hlil = func.hlil
        if hlil is not None and hasattr(hlil, 'root') and hlil.root is not None:
            body_lines = _lines_to_text(hlil.root.lines)
            if body_lines:
                result = _build_header()
                result.extend(f"    {line}" for line in body_lines)
                result.append("}")
                return "\n".join(result)
    except Exception as e:
        _strategy_errors.append(f"S3_hlil_root: {type(e).__name__}: {e}")

    # Strategy 4: iterate hlil.instructions directly
    try:
        hlil = func.hlil
        if hlil is not None:
            body_lines = []
            for insn in hlil.instructions:
                # Each instruction can be converted to text via tokens or str()
                tokens = getattr(insn, 'tokens', None)
                if tokens is not None:
                    body_lines.append("    " + "".join(t.text for t in tokens))
                else:
                    body_lines.append(f"    {insn}")
            if body_lines:
                result = _build_header()
                result.extend(body_lines)
                result.append("}")
                return "\n".join(result)
    except Exception as e:
        _strategy_errors.append(f"S4_hlil_insn: {type(e).__name__}: {e}")

    # Strategy 5: hlil_if_available (non-blocking, may already be cached)
    try:
        hlil = func.hlil_if_available
        if hlil is not None:
            body_lines = []
            try:
                if hasattr(hlil, 'root') and hlil.root is not None:
                    body_lines = [f"    {line}" for line in _lines_to_text(hlil.root.lines)]
            except Exception:
                pass
            if not body_lines:
                try:
                    for insn in hlil.instructions:
                        body_lines.append(f"    {insn}")
                except Exception:
                    pass
            if body_lines:
                result = _build_header()
                result.extend(body_lines)
                result.append("}")
                return "\n".join(result)
    except Exception as e:
        _strategy_errors.append(f"S5_hlil_avail: {type(e).__name__}: {e}")

    # Strategy 6: At least dump MLIL (still much better than raw asm)
    try:
        mlil = func.mlil
        if mlil is not None:
            body_lines = []
            for insn in mlil.instructions:
                body_lines.append(f"    {insn}")
            if body_lines:
                result = [f"// MLIL fallback (HLIL unavailable)"]
                result.extend(_build_header())
                result.extend(body_lines)
                result.append("}")
                return "\n".join(result)
    except Exception as e:
        _strategy_errors.append(f"S6_mlil: {type(e).__name__}: {e}")

    # All 6 strategies failed — log first 20 for diagnostics
    if _decompile_diag_count < 20:
        log_warn(f"[{PLUGIN_NAME}] ALL 6 strategies failed for {name} @ 0x{func.start:X}: {' | '.join(_strategy_errors)}")
        _decompile_diag_count += 1

    return None


def get_function_decompiled_linear(bv: BinaryView, func: Function) -> Optional[str]:
    """Get decompiled output via Binary Ninja's Linear View.

    Uses single_function_language_representation for precise per-function output.
    This is the absolute cleanest representation — it's what you see in the
    Linear View in the GUI with full type annotations, casts, etc.
    IDA has nothing equivalent.
    """
    # Approach A: single_function_language_representation (precise, per-function)
    try:
        settings = bn.DisassemblySettings()
        settings.set_option(bn.DisassemblyOption.ShowAddress, False)
        lv = bn.LinearViewObject.single_function_language_representation(func, settings)
        cursor = bn.LinearViewCursor(lv)
        cursor.seek_to_begin()

        out = []
        while not cursor.after_end:
            cur_lines = cursor.lines
            if cur_lines:
                for line in cur_lines:
                    dtl = getattr(line, 'contents', line)
                    tokens = getattr(dtl, 'tokens', None)
                    if tokens is not None:
                        out.append("".join(t.text for t in tokens))
                    else:
                        out.append(str(line))
            if not cursor.next():
                break

        if out:
            return "\n".join(out)
    except Exception:
        pass

    # Approach B: Full view cursor seek (fallback if single_function fails)
    try:
        settings = bn.DisassemblySettings()
        settings.set_option(bn.DisassemblyOption.ShowAddress, False)
        lv = bn.LinearViewObject.language_representation(bv, settings)
        cursor = bn.LinearViewCursor(lv)
        cursor.seek_to_address(func.start)

        out = []
        while cursor.valid:
            cur_lines = cursor.lines
            if cur_lines:
                for line in cur_lines:
                    dtl = getattr(line, 'contents', line)
                    addr = getattr(dtl, 'address', 0)
                    # Stop if we've passed the function
                    if addr > func.highest_address and len(out) > 2:
                        return "\n".join(out)
                    tokens = getattr(dtl, 'tokens', None)
                    if tokens is not None:
                        out.append("".join(t.text for t in tokens))
                    else:
                        out.append(str(line))
            if not cursor.next():
                break

        return "\n".join(out) if out else None
    except Exception:
        return None


# ============================================================================
# IL PIPELINE EXTRACTION (Binary Ninja's deobfuscation chain)
# ============================================================================

def get_function_il_pipeline(bv: BinaryView, func: Function) -> Optional[str]:
    """Dump the full IL pipeline: LLIL → MLIL → HLIL.

    This is THE thing Binary Ninja does that IDA cannot:
    - LLIL: Lifted IL, close to assembly but regularized
    - MLIL: Medium Level IL, with type propagation and simplification
    - HLIL: High Level IL, fully deobfuscated C-like code

    Each level applies more transformations, so you can see exactly
    how Binja deobfuscated the code step by step.
    """
    lines = []
    name = func_name(func)

    # --- LLIL ---
    try:
        llil = func.llil
        if llil:
            lines.append("// ===== LLIL (Lifted Low-Level IL) =====")
            lines.append("// Close to assembly, but normalized registers/flags")
            for i, insn in enumerate(llil.instructions):
                lines.append(f"    {i:4d}: {insn}")
            lines.append("")
    except Exception:
        lines.append("// LLIL: not available")
        lines.append("")

    # --- MLIL ---
    try:
        mlil = func.mlil
        if mlil:
            lines.append("// ===== MLIL (Medium-Level IL) =====")
            lines.append("// Variables recovered, types propagated, expressions simplified")
            for i, insn in enumerate(mlil.instructions):
                lines.append(f"    {i:4d}: {insn}")
            lines.append("")
    except Exception:
        lines.append("// MLIL: not available")
        lines.append("")

    # --- MLIL SSA ---
    try:
        mlil_ssa = func.mlil.ssa_form
        if mlil_ssa:
            lines.append("// ===== MLIL SSA (Static Single Assignment) =====")
            lines.append("// Each variable version tracked — shows data flow precisely")
            for i, insn in enumerate(mlil_ssa.instructions):
                lines.append(f"    {i:4d}: {insn}")
            lines.append("")
    except Exception:
        pass

    # --- HLIL ---
    try:
        hlil = func.hlil
        if hlil:
            lines.append("// ===== HLIL (High-Level IL — Deobfuscated) =====")
            lines.append("// Dead code removed, constants folded, control flow recovered")
            # Try pseudo_c first (cleanest Pseudo C output)
            got_hlil = False
            try:
                lang_rep = func.pseudo_c
                if lang_rep is not None and hlil.root is not None:
                    for dtl in lang_rep.get_linear_lines(hlil.root):
                        tokens = getattr(dtl, 'tokens', None)
                        if tokens is not None:
                            lines.append("    " + "".join(t.text for t in tokens))
                        else:
                            lines.append(f"    {dtl}")
                    got_hlil = True
            except Exception:
                pass
            # Fallback to hlil.root.lines with proper token extraction
            if not got_hlil:
                try:
                    if hlil.root is not None:
                        for dtl in hlil.root.lines:
                            tokens = getattr(dtl, 'tokens', None)
                            if tokens is not None:
                                lines.append("    " + "".join(t.text for t in tokens))
                            else:
                                lines.append(f"    {dtl}")
                        got_hlil = True
                except Exception:
                    pass
            # Last resort: iterate instructions
            if not got_hlil:
                for i, insn in enumerate(hlil.instructions):
                    lines.append(f"    {i:4d}: {insn}")
            lines.append("")
    except Exception:
        lines.append("// HLIL: not available")
        lines.append("")

    return "\n".join(lines) if lines else None


# ============================================================================
# DUMP TASKS — New dumps that IDA doesn't have
# ============================================================================

class DumpBinaryOverviewTask(BackgroundTaskThread):
    """Dump binary overview/triage: arch, platform, entry, hashes, summary."""
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping binary overview...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_OVERVIEW.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping binary overview to: {filepath}")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("BINARY OVERVIEW / TRIAGE\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"File:           {bv.file.filename}\n")
            f.write(f"File Format:    {bv.view_type}\n")
            f.write(f"Architecture:   {bv.arch.name if bv.arch else 'unknown'}\n")
            f.write(f"Platform:       {bv.platform.name if bv.platform else 'unknown'}\n")
            f.write(f"Address Size:   {bv.address_size * 8}-bit\n")
            f.write(f"Endianness:     {'Little' if bv.endianness == bn.Endianness.LittleEndian else 'Big'}\n")
            f.write(f"Entry Point:    0x{bv.entry_point:X}\n")
            f.write(f"Start Address:  0x{bv.start:X}\n")
            f.write(f"End Address:    0x{bv.end:X}\n")
            f.write(f"Image Size:     {bv.end - bv.start} bytes ({(bv.end - bv.start) / 1024 / 1024:.2f} MB)\n")
            f.write(f"File Length:    {bv.length} bytes\n")
            f.write("\n")

            # Hashes of the binary file
            try:
                raw = bv.file.raw
                if raw:
                    full_data = raw.read(0, raw.length)
                    if full_data:
                        f.write(f"MD5:            {hashlib.md5(full_data).hexdigest()}\n")
                        f.write(f"SHA1:           {hashlib.sha1(full_data).hexdigest()}\n")
                        f.write(f"SHA256:         {hashlib.sha256(full_data).hexdigest()}\n")
                        f.write("\n")
            except Exception:
                pass

            # Counts
            f.write("-" * 40 + "\n")
            f.write("DATABASE STATISTICS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Functions:      {len(bv.functions)}\n")
            f.write(f"Symbols:        {len(bv.get_symbols())}\n")
            f.write(f"Strings:        {len(bv.strings)}\n")
            f.write(f"Sections:       {len(bv.sections)}\n")
            f.write(f"Segments:       {len(bv.segments)}\n")
            f.write(f"Types:          {len(bv.types)}\n")
            f.write(f"Data Variables: {len(bv.data_vars)}\n")
            try:
                tag_count = len(list(bv.get_all_tag_references()))
            except AttributeError:
                try:
                    tag_count = sum(len(list(f.tag_refs)) for f in bv.functions)
                except Exception:
                    tag_count = 0
            f.write(f"Tags:           {tag_count}\n")
            f.write("\n")

            # Libraries / dependencies
            f.write("-" * 40 + "\n")
            f.write("IMPORTED LIBRARIES\n")
            f.write("-" * 40 + "\n")
            libs = set()
            for sym in bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol):
                ns = sym.namespace
                if ns:
                    libs.add(ns)
            for lib in sorted(libs):
                f.write(f"  {lib}\n")
            f.write(f"\nTotal libraries: {len(libs)}\n")

            # Entry points / exported function list
            f.write("\n" + "-" * 40 + "\n")
            f.write("ENTRY POINTS / EXPORTS (first 100)\n")
            f.write("-" * 40 + "\n")
            export_count = 0
            for sym in bv.get_symbols_of_type(SymbolType.FunctionSymbol):
                if sym.binding == bn.SymbolBinding.GlobalBinding:
                    f.write(f"  0x{sym.address:X}\t{sym.full_name or sym.short_name}\n")
                    export_count += 1
            f.write(f"\n")

            # Section breakdown
            f.write("-" * 40 + "\n")
            f.write("SECTION MAP\n")
            f.write("-" * 40 + "\n")
            f.write(f"{'Name':<20} {'Start':>18} {'End':>18} {'Size':>12} {'Sem'}\n")
            for section in bv.sections.values():
                start = section.start
                end = section.end
                size = end - start
                sem = section.semantics
                sem_map = {
                    bn.SectionSemantics.ReadOnlyCodeSectionSemantics: "R-X (code)",
                    bn.SectionSemantics.ReadOnlyDataSectionSemantics: "R-- (rodata)",
                    bn.SectionSemantics.ReadWriteDataSectionSemantics: "RW- (data)",
                    bn.SectionSemantics.ExternalSectionSemantics: "EXT (extern)",
                }
                sem_str = sem_map.get(sem, "---")
                f.write(f"{section.name or '?':<20} {start:018X} {end:018X} {size:>12} {sem_str}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Overview DONE → {filepath}")


class DumpAllDataVariablesTask(BackgroundTaskThread):
    """Dump ALL data variables — globals, statics, constants with types and values."""
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping data variables...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_DATA_VARIABLES.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping data variables to: {filepath}")

        aw = _addr_w(bv)
        count = 0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL DATA VARIABLES DUMP\n")
            f.write(f"Binary: {bv.file.filename}\n")
            f.write("=" * 80 + "\n\n")

            for addr in sorted(bv.data_vars.keys()):
                if self.cancelled:
                    break
                if count % 5000 == 0:
                    self.progress = f"Data variables... {count}"
                    if count > 0:
                        log_info(f"[{PLUGIN_NAME}]   Data vars: {count} dumped...")

                count += 1
                dv = bv.data_vars[addr]
                type_str = str(dv.type) if dv.type else "?"
                size = dv.type.width if dv.type else 0

                # Get symbol name if any
                sym = bv.get_symbol_at(addr)
                sym_name = ""
                if sym:
                    sym_name = sym.full_name or sym.short_name or sym.raw_name

                # Section
                sections = bv.get_sections_at(addr)
                seg = sections[0].name if sections else "?"

                # Try to read the value
                val_str = ""
                if dv.type:
                    # Check if it's a string
                    s = bv.get_string_at(addr)
                    if s:
                        content = bv.read(s.start, min(s.length, 120))
                        val_str = f'= "{_safe_str(content)}"'
                    elif size <= 8 and size > 0:
                        raw = bv.read(addr, size)
                        if raw:
                            val = int.from_bytes(raw, "little" if bv.endianness == bn.Endianness.LittleEndian else "big")
                            val_str = f"= 0x{val:X} ({val})"

                line = f"{seg}:{addr:0{aw}X}  {type_str:<30}"
                if sym_name:
                    line += f"  {sym_name}"
                if val_str:
                    line += f"  {val_str}"
                f.write(line + "\n")

            f.write(f"\nTotal data variables: {count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Data variables DONE: {count} → {filepath}")


class DumpAllCallGraphTask(BackgroundTaskThread):
    """Dump complete call graph — every caller→callee edge."""
    def __init__(self, bv: BinaryView):
        super().__init__("Building call graph...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_CALL_GRAPH.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping call graph to: {filepath}")

        funcs = list(bv.functions)
        total = len(funcs)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("COMPLETE CALL GRAPH\n")
            f.write(f"Binary: {bv.file.filename}\n")
            f.write(f"Total functions: {total}\n")
            f.write("=" * 80 + "\n")
            f.write("Format: CALLER → CALLEE\n\n")

            edge_count = 0
            for i, func in enumerate(funcs):
                if self.cancelled:
                    break
                if i % 500 == 0:
                    pct = int(i / total * 100) if total else 0
                    self.progress = f"Call graph... {i}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   Call graph: {i}/{total} ({pct}%)")

                caller = func_name(func)
                callees = func.callees
                if callees:
                    for callee in callees:
                        f.write(f"0x{func.start:X} {caller} → 0x{callee.start:X} {func_name(callee)}\n")
                        edge_count += 1

            f.write(f"\nTotal edges: {edge_count}\n")
            f.write(f"Total nodes: {total}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Call graph DONE: {edge_count} edges → {filepath}")


class DumpAllFunctionDetailsTask(BackgroundTaskThread):
    """Dump rich per-function details: locals, stack frame, calling convention, types."""
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping function details...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_FUNCTIONS_DETAIL.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping function details to: {filepath}")

        funcs = list(bv.functions)
        total = len(funcs)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL FUNCTION DETAILS\n")
            f.write(f"Binary: {bv.file.filename}\n")
            f.write(f"Total functions: {total}\n")
            f.write("=" * 80 + "\n")
            f.write("Includes: signature, calling convention, local variables,\n")
            f.write("stack frame, basic block count, recovered types\n\n")

            for i, func in enumerate(funcs):
                if self.cancelled:
                    break
                if i % 500 == 0:
                    pct = int(i / total * 100) if total else 0
                    self.progress = f"Function details... {i}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   Function details: {i}/{total} ({pct}%)")

                name = func_name(func)
                f.write("/" + "-" * 78 + "/\n")
                f.write(f"[FUNC] {name}\n")
                f.write(f"  Address:      0x{func.start:X} - 0x{func.highest_address:X}\n")
                f.write(f"  Size:         {func.total_bytes} bytes\n")
                f.write(f"  Basic Blocks: {len(list(func.basic_blocks))}\n")

                # Calling convention
                cc = func.calling_convention
                f.write(f"  Calling Conv: {cc.name if cc else 'unknown'}\n")

                # Return type
                ret = func.return_type
                f.write(f"  Return Type:  {ret if ret else 'void'}\n")

                # Parameters
                params = func.parameter_vars
                if params:
                    f.write(f"  Parameters ({len(params)}):\n")
                    for p in params:
                        ptype = str(p.type) if p.type else "?"
                        f.write(f"    {ptype} {p.name}\n")

                # Local variables (Binja's type recovery)
                stack_vars = [v for v in func.vars if v.source_type == bn.VariableSourceType.StackVariableSourceType]
                reg_vars = [v for v in func.vars if v.source_type == bn.VariableSourceType.RegisterVariableSourceType]

                if stack_vars:
                    f.write(f"  Stack Variables ({len(stack_vars)}):\n")
                    for v in sorted(stack_vars, key=lambda x: x.storage):
                        vtype = str(v.type) if v.type else "?"
                        f.write(f"    [{v.storage:#06x}] {vtype} {v.name}\n")

                if reg_vars:
                    f.write(f"  Register Variables ({len(reg_vars)}):\n")
                    for v in reg_vars:
                        vtype = str(v.type) if v.type else "?"
                        f.write(f"    {vtype} {v.name}\n")

                # Function flags/attributes
                attrs = []
                if func.can_return == bn.BoolWithConfidence(False):
                    attrs.append("noreturn")
                if func.has_variable_arguments:
                    attrs.append("variadic")
                if func.analysis_skipped:
                    attrs.append("analysis_skipped")
                if attrs:
                    f.write(f"  Attributes:   {', '.join(attrs)}\n")

                # Strings referenced
                str_refs = _get_func_string_refs(bv, func)
                if str_refs:
                    f.write(f"  Strings ({len(str_refs)}):\n")
                    for _saddr, sr in str_refs:
                        sr_clean = sr.replace('\n', '\\n').replace('\r', '\\r')
                        f.write(f'    "{sr_clean}"\n')

                f.write("\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Function details DONE: {total} functions → {filepath}")


class DumpAllCommentsAndTagsTask(BackgroundTaskThread):
    """Dump ALL comments (function-level, address-level) and Binary Ninja tags."""
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting comments & tags...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_COMMENTS_TAGS.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping comments & tags to: {filepath}")

        aw = _addr_w(bv)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL COMMENTS AND TAGS\n")
            f.write("=" * 80 + "\n\n")

            # Function-level comments
            f.write("-" * 40 + "\n")
            f.write("FUNCTION COMMENTS\n")
            f.write("-" * 40 + "\n")
            func_comment_count = 0
            for func in bv.functions:
                if self.cancelled:
                    break
                comment = func.comment
                if comment:
                    func_comment_count += 1
                    f.write(f"\n[{func_name(func)}] 0x{func.start:X}\n")
                    for line in comment.split('\n'):
                        f.write(f"  {line}\n")
            f.write(f"\nTotal function comments: {func_comment_count}\n")

            # Address-level comments from functions
            f.write("\n" + "-" * 40 + "\n")
            f.write("ADDRESS COMMENTS (in functions)\n")
            f.write("-" * 40 + "\n")
            addr_comment_count = 0
            for func in bv.functions:
                if self.cancelled:
                    break
                for addr, comment in func.comments.items():
                    addr_comment_count += 1
                    f.write(f"  0x{addr:0{aw}X}  [{func_name(func)}]  {comment}\n")
            f.write(f"\nTotal address comments: {addr_comment_count}\n")

            # Global comments (not in any function)
            f.write("\n" + "-" * 40 + "\n")
            f.write("GLOBAL ADDRESS COMMENTS\n")
            f.write("-" * 40 + "\n")
            global_comment_count = 0
            try:
                addr_ranges = bv.address_comments
                for addr in addr_ranges:
                    global_comment_count += 1
                    comment = bv.get_comment_at(addr)
                    f.write(f"  0x{addr:0{aw}X}  {comment}\n")
            except (AttributeError, TypeError):
                # Fallback: scan segments for comments
                for seg in bv.segments:
                    for addr in range(seg.start, seg.end, bv.address_size):
                        comment = bv.get_comment_at(addr)
                        if comment:
                            global_comment_count += 1
                            f.write(f"  0x{addr:0{aw}X}  {comment}\n")
            f.write(f"\nTotal global comments: {global_comment_count}\n")

            # Tags
            f.write("\n" + "-" * 40 + "\n")
            f.write("TAGS / BOOKMARKS\n")
            f.write("-" * 40 + "\n")
            tag_count = 0
            try:
                # Try the direct API first
                tag_refs = list(bv.get_all_tag_references())
                for tag_ref in tag_refs:
                    tag_count += 1
                    tag = tag_ref.tag
                    f.write(f"  0x{tag_ref.addr:0{aw}X}  [{tag.type.name}] {tag.data}\n")
            except AttributeError:
                # Fallback: iterate functions for tag refs
                try:
                    for func in bv.functions:
                        try:
                            for ref in func.tag_refs:
                                tag_count += 1
                                f.write(f"  0x{ref.addr:0{aw}X}  [{ref.tag.type.name}] {ref.tag.data}\n")
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                pass
            f.write(f"\nTotal tags: {tag_count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Comments/tags DONE → {filepath}")


class DumpAllILPipelineTask(BackgroundTaskThread):
    """Dump the IL pipeline (LLIL → MLIL → HLIL) for every function.

    This is Binary Ninja's killer feature — the progressive deobfuscation
    chain that IDA simply does not have.
    """
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping IL pipeline...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_IL_PIPELINE.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping IL pipeline to: {filepath}")

        funcs = list(bv.functions)
        total = len(funcs)
        success = failed = 0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("/" + "*" * 78 + "/\n")
            f.write("/* BINARY NINJA IL PIPELINE DUMP */\n")
            f.write("/* LLIL → MLIL → MLIL-SSA → HLIL for every function */\n")
            f.write("/* This shows the progressive deobfuscation/simplification chain */\n")
            f.write("/" + "*" * 78 + "/\n\n")

            for i, func in enumerate(funcs):
                if self.cancelled:
                    break
                if i % 500 == 0:
                    pct = int(i / total * 100) if total else 0
                    self.progress = f"IL pipeline... {i}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   IL pipeline: {i}/{total} ({pct}%) — {success} ok")

                name = func_name(func)
                try:
                    il = get_function_il_pipeline(bv, func)
                    if il:
                        f.write("/" + "-" * 78 + "/\n")
                        f.write(f"// Function: {name}\n")
                        f.write(f"// Address: 0x{func.start:X}\n\n")
                        f.write(il + "\n\n")
                        success += 1
                    else:
                        failed += 1
                except Exception:
                    failed += 1

            f.write(f"\n/* IL dump complete: {success}/{total} functions ({failed} failed) */\n")

        log_info(f"[{PLUGIN_NAME}] ✓ IL pipeline DONE: {success}/{total} → {filepath}")


class DumpAllStringXrefsTask(BackgroundTaskThread):
    """Dump string→function cross-reference map.

    For EVERY string: which functions reference it.
    Way more useful than just a string list.
    """
    def __init__(self, bv: BinaryView):
        super().__init__("Building string xref map...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_STRING_XREFS.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping string xrefs to: {filepath}")

        aw = _addr_w(bv)
        strings = list(bv.strings)
        total = len(strings)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("STRING → FUNCTION CROSS-REFERENCE MAP\n")
            f.write(f"Total strings: {total}\n")
            f.write("=" * 80 + "\n\n")

            strings_with_refs = 0
            for si, s in enumerate(strings):
                if self.cancelled:
                    break
                if si % 5000 == 0:
                    pct = int(si / total * 100) if total else 0
                    self.progress = f"String xrefs... {si}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   String xrefs: {si}/{total} ({pct}%) — {strings_with_refs} with refs")

                content = bv.read(s.start, min(s.length, 200))
                if not content:
                    continue
                text = _safe_str(content).replace('\n', '\\n').replace('\r', '\\r')

                # Find all code references to this string
                refs = list(bv.get_code_refs(s.start))
                # Also check data refs pointing to the string
                # NOTE: get_data_refs returns plain int addresses, not objects
                data_refs = list(bv.get_data_refs(s.start))

                # Find which functions contain the code refs
                func_refs: Set[str] = set()
                for ref in refs:
                    for cf in bv.get_functions_containing(ref.address):
                        func_refs.add(f"0x{cf.start:X} {func_name(cf)}")

                # For data refs, check if any function references that data
                for dref_addr in data_refs:
                    code_to_data = list(bv.get_code_refs(dref_addr))
                    for cref in code_to_data:
                        for cf in bv.get_functions_containing(cref.address):
                            func_refs.add(f"0x{cf.start:X} {func_name(cf)}")

                if func_refs:
                    strings_with_refs += 1
                    f.write(f'[STRING] 0x{s.start:0{aw}X} "{text}"\n')
                    f.write(f"  Referenced by ({len(func_refs)}):\n")
                    for fr in sorted(func_refs):
                        f.write(f"    {fr}\n")
                    f.write("\n")

            f.write(f"\nStrings with references: {strings_with_refs}/{total}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ String xrefs DONE: {strings_with_refs}/{total} strings → {filepath}")


class DumpAllTypesTask(BackgroundTaskThread):
    """Dump ALL types — structs, unions, enums, typedefs, function pointers, arrays.

    Not just structs like the basic dump — EVERYTHING in the type library.
    """
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping all types...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_TYPES.txt")
        log_info(f"[{PLUGIN_NAME}] Dumping all types to: {filepath}")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("COMPLETE TYPE LIBRARY DUMP\n")
            f.write(f"Total types: {len(bv.types)}\n")
            f.write("=" * 80 + "\n\n")

            structs = []
            enums = []
            typedefs = []
            func_types = []
            other_types = []

            for type_name, type_obj in bv.types.items():
                if self.cancelled:
                    break

                t = type_obj
                if hasattr(t, 'structure') and t.structure is not None:
                    structs.append((str(type_name), t))
                elif hasattr(t, 'enumeration') and t.enumeration is not None:
                    enums.append((str(type_name), t))
                elif hasattr(t, 'type_class'):
                    tc = t.type_class
                    if tc == bn.TypeClass.NamedTypeReferenceClass:
                        typedefs.append((str(type_name), t))
                    elif tc == bn.TypeClass.FunctionTypeClass:
                        func_types.append((str(type_name), t))
                    else:
                        other_types.append((str(type_name), t))
                else:
                    other_types.append((str(type_name), t))

            # Structs & Unions
            f.write("=" * 40 + " STRUCTS & UNIONS " + "=" * 40 + "\n\n")
            for tname, t in sorted(structs, key=lambda x: x[0]):
                struct = t.structure
                kind = "union" if struct.union else "struct"
                f.write(f"{kind} {tname} {{ // size: {struct.width} bytes\n")
                for member in struct.members:
                    mname = member.name or f"field_{member.offset:X}"
                    mtype = str(member.type) if member.type else "?"
                    f.write(f"    /* +0x{member.offset:04X} */  {mtype} {mname};\n")
                f.write(f"}};\n\n")

            # Enums
            f.write("=" * 40 + " ENUMS " + "=" * 40 + "\n\n")
            for tname, t in sorted(enums, key=lambda x: x[0]):
                enum = t.enumeration
                f.write(f"enum {tname} {{\n")
                for member in enum.members:
                    f.write(f"    {member.name} = 0x{member.value:X},  // {member.value}\n")
                f.write(f"}};\n\n")

            # Function types
            f.write("=" * 40 + " FUNCTION TYPES " + "=" * 40 + "\n\n")
            for tname, t in sorted(func_types, key=lambda x: x[0]):
                f.write(f"typedef {t}; // {tname}\n")
            f.write("\n")

            # Typedefs
            f.write("=" * 40 + " TYPEDEFS " + "=" * 40 + "\n\n")
            for tname, t in sorted(typedefs, key=lambda x: x[0]):
                f.write(f"typedef {t} {tname};\n")
            f.write("\n")

            # Other
            if other_types:
                f.write("=" * 40 + " OTHER TYPES " + "=" * 40 + "\n\n")
                for tname, t in sorted(other_types, key=lambda x: x[0]):
                    f.write(f"{tname} = {t}\n")
                f.write("\n")

            f.write(f"\nSummary: {len(structs)} structs, {len(enums)} enums, "
                    f"{len(func_types)} func types, {len(typedefs)} typedefs, "
                    f"{len(other_types)} other\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Types DONE → {filepath}")


# ============================================================================
# DUMP TASKS — Original dumps (Assembly, Decompiled, Strings, etc.)
# ============================================================================

class DumpAllAssemblyTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping all assembly...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_ASSEMBLY.asm")
        log_info(f"[{PLUGIN_NAME}] Dumping all assembly to: {filepath}")

        funcs = list(bv.functions)
        total = len(funcs)
        success = 0
        log_info(f"[{PLUGIN_NAME}] ▶ Assembly: starting {total} functions...")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(";" + "=" * 79 + "\n")
            f.write("; ALL ASSEMBLY DUMP\n")
            f.write(f"; Binary: {bv.file.filename}\n")
            f.write(f"; Total functions: {total}\n")
            f.write(";" + "=" * 79 + "\n\n")

            for i, func in enumerate(funcs):
                if self.cancelled:
                    break
                if i % 500 == 0:
                    pct = int(i / total * 100) if total else 0
                    self.progress = f"Dumping assembly... {i}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   Assembly: {i}/{total} ({pct}%) — {success} written")
                asm = get_function_assembly(bv, func)
                if asm:
                    f.write(";" + "-" * 79 + "\n")
                    f.write(asm + "\n\n")
                    success += 1

            f.write(f"\n; Dump complete: {success}/{total} functions\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Assembly dump DONE: {success}/{total} → {filepath}")


class DumpAllDecompiledTask(BackgroundTaskThread):
    """Dump ALL decompiled functions using HLIL with full variable declarations.
    Functions that can't be decompiled are SKIPPED — assembly is in ALL_ASSEMBLY.asm."""
    def __init__(self, bv: BinaryView):
        super().__init__("Decompiling all functions...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_DECOMPILED.c")
        log_info(f"[{PLUGIN_NAME}] Dumping all decompiled to: {filepath}")

        funcs = list(bv.functions)
        total = len(funcs)
        success = failed = 0
        diag_logged = 0  # limit diagnostic exception logging
        log_info(f"[{PLUGIN_NAME}] ▶ Decompiled: starting {total} functions...")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("/" + "*" * 78 + "/\n")
            f.write("/* ALL DECOMPILED DUMP (Binary Ninja HLIL) */\n")
            f.write("/* Includes: recovered types, local variables, */\n")
            f.write("/* deobfuscated control flow, simplified expressions */\n")
            f.write("/* Functions that fail decompilation are SKIPPED (asm is in ALL_ASSEMBLY.asm) */\n")
            f.write(f"/* Binary: {bv.file.filename} */\n")
            f.write(f"/* Total functions: {total} */\n")
            f.write("/" + "*" * 78 + "/\n\n")

            for i, func in enumerate(funcs):
                if self.cancelled:
                    break
                if i % 500 == 0:
                    pct = int(i / total * 100) if total else 0
                    self.progress = f"Decompiling... {i}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   Decompiled: {i}/{total} ({pct}%) — {success} ok, {failed} failed")

                name = func_name(func)
                try:
                    decompiled = get_function_decompiled(bv, func)
                    if decompiled:
                        f.write("/" + "-" * 78 + "/\n")
                        f.write(f"// Function: {name}\n")
                        f.write(f"// Address: 0x{func.start:X}\n")

                        # Include strings referenced (AI context)
                        try:
                            str_refs = _get_func_string_refs(bv, func)
                            if str_refs:
                                str_strs = [s.replace('\n', '\\n') for _, s in str_refs]
                                f.write(f"// Strings: {str_strs}\n")
                        except Exception:
                            pass

                        f.write("\n")
                        f.write(decompiled + "\n\n")
                        success += 1
                    else:
                        # Decompilation returned None — SKIP, assembly is in ALL_ASSEMBLY.asm
                        failed += 1
                except Exception as ex:
                    if diag_logged < 10:
                        log_warn(f"[{PLUGIN_NAME}] DIAG EXCEPTION: {name} @ 0x{func.start:X} — {type(ex).__name__}: {ex}")
                        diag_logged += 1
                    failed += 1

            f.write(f"\n/* Dump complete: {success} decompiled, {failed} failed (of {total}) */\n")
            f.write(f"/* Failed functions are NOT included — check ALL_ASSEMBLY.asm for those */\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Decompiled DONE: {success} decompiled, {failed} failed = {total} → {filepath}")


class DumpAllStringsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting strings...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_STRINGS.txt")
        aw = _addr_w(bv)
        count = 0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL STRINGS DUMP\n")
            f.write(f"Binary: {bv.file.filename}\n")
            f.write("=" * 80 + "\n\n")

            for s in bv.strings:
                if self.cancelled:
                    break
                if count % 10000 == 0:
                    self.progress = f"Collecting strings... {count}"
                    if count > 0:
                        log_info(f"[{PLUGIN_NAME}]   Strings: {count} collected...")
                count += 1
                content = bv.read(s.start, s.length)
                if content:
                    text = _safe_str(content)
                    sections = bv.get_sections_at(s.start)
                    seg = sections[0].name if sections else "?"
                    f.write(f"{seg}:{s.start:0{aw}X}\t{s.length:04d}\t{text}\n")

            f.write(f"\nTotal strings: {count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Strings DONE: {count} → {filepath}")


class DumpAllNamesTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting names...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_NAMES.txt")
        aw = _addr_w(bv)
        count = 0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL NAMES DUMP\n")
            f.write("=" * 80 + "\n\n")

            type_map = {
                SymbolType.FunctionSymbol: "FUNC",
                SymbolType.ImportedFunctionSymbol: "IMPORT",
                SymbolType.ImportAddressSymbol: "IAT",
                SymbolType.DataSymbol: "DATA",
                SymbolType.ImportedDataSymbol: "IDATA",
                SymbolType.ExternalSymbol: "EXTERN",
                SymbolType.LibraryFunctionSymbol: "LIBFUNC",
            }

            for sym in bv.get_symbols():
                if self.cancelled:
                    break
                if count % 10000 == 0:
                    self.progress = f"Collecting names... {count}"
                    if count > 0:
                        log_info(f"[{PLUGIN_NAME}]   Names: {count} collected...")
                count += 1
                name = sym.full_name or sym.short_name or sym.raw_name
                item_type = type_map.get(sym.type, "UNKN")
                sections = bv.get_sections_at(sym.address)
                seg = sections[0].name if sections else "?"
                f.write(f"{seg}:{sym.address:0{aw}X}\t{item_type}\t{name}\n")

            f.write(f"\nTotal names: {count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Names DONE: {count} → {filepath}")


class DumpAllImportsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting imports...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_IMPORTS.txt")
        aw = _addr_w(bv)
        count = 0
        imports_by_lib: Dict[str, List[Tuple[int, str]]] = {}

        for sym in bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol):
            count += 1
            ns = sym.namespace or "unknown"
            name = sym.full_name or sym.short_name or sym.raw_name
            imports_by_lib.setdefault(ns, []).append((sym.address, name))

        for sym in bv.get_symbols_of_type(SymbolType.ImportAddressSymbol):
            ns = sym.namespace or "unknown"
            name = sym.full_name or sym.short_name or sym.raw_name
            imports_by_lib.setdefault(ns, []).append((sym.address, name))
            count += 1

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL IMPORTS DUMP\n")
            f.write("=" * 80 + "\n\n")
            for lib in sorted(imports_by_lib.keys()):
                entries = imports_by_lib[lib]
                f.write(f"\n[MODULE] {lib}\n")
                f.write("-" * 60 + "\n")
                for addr, name in sorted(entries):
                    f.write(f"  {addr:0{aw}X}\t{name}\n")
            f.write(f"\nTotal imports: {count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Imports DONE: {count} → {filepath}")


class DumpAllExportsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting exports...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_EXPORTS.txt")
        aw = _addr_w(bv)
        count = 0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL EXPORTS DUMP\n")
            f.write("=" * 80 + "\n\n")
            for sym in bv.get_symbols_of_type(SymbolType.FunctionSymbol):
                if sym.binding == bn.SymbolBinding.GlobalBinding:
                    count += 1
                    f.write(f"{sym.address:0{aw}X}\t{sym.full_name or sym.short_name}\n")
            for sym in bv.get_symbols_of_type(SymbolType.ExternalSymbol):
                count += 1
                f.write(f"{sym.address:0{aw}X}\t{sym.full_name or sym.short_name}\n")
            f.write(f"\nTotal exports: {count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Exports DONE: {count} → {filepath}")


class DumpAllSegmentsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting segments...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_SEGMENTS.txt")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL SEGMENTS DUMP\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"{'Name':<20} {'Start':>18} {'End':>18} {'Size':>12} {'Perms'}\n")
            f.write("-" * 80 + "\n")
            count = 0
            for section in bv.sections.values():
                count += 1
                start = section.start
                end = section.end
                sem = section.semantics
                sem_map = {
                    bn.SectionSemantics.ReadOnlyCodeSectionSemantics: "R-X",
                    bn.SectionSemantics.ReadOnlyDataSectionSemantics: "R--",
                    bn.SectionSemantics.ReadWriteDataSectionSemantics: "RW-",
                    bn.SectionSemantics.ExternalSectionSemantics: "EXT",
                }
                perms = sem_map.get(sem, "---")
                f.write(f"{section.name or '?':<20} {start:018X} {end:018X} {end - start:>12} {perms}\n")
            f.write(f"\nTotal sections: {count}\n\n")

            f.write("RAW SEGMENTS\n" + "-" * 80 + "\n")
            f.write(f"{'Start':>18} {'End':>18} {'DataOff':>12} {'DataLen':>12} {'Flags'}\n")
            sc = 0
            for seg in bv.segments:
                sc += 1
                flags = ("R" if seg.readable else "") + ("W" if seg.writable else "") + ("X" if seg.executable else "")
                f.write(f"{seg.start:018X} {seg.end:018X} {seg.data_offset:>12} {seg.data_length:>12} {flags}\n")
            f.write(f"\nTotal segments: {sc}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Segments DONE → {filepath}")


class DumpAllXrefsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting xrefs...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_XREFS.txt")
        funcs = list(bv.functions)
        total = len(funcs)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL CROSS-REFERENCES DUMP\n")
            f.write("=" * 80 + "\n\n")

            for i, func in enumerate(funcs):
                if self.cancelled:
                    break
                if i % 500 == 0:
                    pct = int(i / total * 100) if total else 0
                    self.progress = f"Collecting xrefs... {i}/{total} ({pct}%)"
                    log_info(f"[{PLUGIN_NAME}]   Xrefs: {i}/{total} ({pct}%)")

                name = func_name(func)
                callers = []
                for ref in bv.get_code_refs(func.start):
                    for cf in bv.get_functions_containing(ref.address):
                        callers.append((ref.address, func_name(cf)))
                callees = set()
                for ref in func.callees:
                    callees.add((ref.start, func_name(ref)))

                if callers or callees:
                    f.write(f"\n[FUNC] {name} (0x{func.start:X})\n")
                    if callers:
                        f.write(f"  Called by ({len(callers)}):\n")
                        for addr, cn in sorted(callers):
                            f.write(f"    {addr:016X} {cn}\n")
                    if callees:
                        f.write(f"  Calls ({len(callees)}):\n")
                        for addr, cn in sorted(callees):
                            f.write(f"    {addr:016X} {cn}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Xrefs DONE → {filepath}")


class DumpAllVTablesTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Scanning for vtables...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_VTABLES.txt")
        aw = _addr_w(bv)
        ps = bv.address_size
        vtables = []
        count = 0

        for sym in bv.get_symbols():
            if self.cancelled:
                break
            count += 1
            name = sym.full_name or sym.raw_name or ""

            if "vftable" in name.lower() or "vtbl" in name.lower() or name.startswith("??_7"):
                class_name = name
                m = re.search(r'\?\?_7([^@]+)@@', name)
                if m:
                    class_name = m.group(1)
                vtables.append((sym.address, name, class_name))
            elif ".?AV" in name or ".?AU" in name:
                m = re.search(r'\.?\?A[VU]([^@]+)@@', name)
                class_name = m.group(1) if m else name
                vtables.append((sym.address, name, class_name))
            elif "_ZTV" in name or "_ZTI" in name:
                vtables.append((sym.address, name, name))

        vtables.sort(key=lambda x: x[2])

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL VTABLES DUMP\n")
            f.write("=" * 80 + "\n\n")

            current = None
            for ea, full_name, class_name in vtables:
                if class_name != current:
                    f.write(f"\n[CLASS] {class_name}\n" + "-" * 60 + "\n")
                    current = class_name
                f.write(f"  {ea:0{aw}X}\t{full_name}\n")

                if "vftable" in full_name.lower() or "vtbl" in full_name.lower() or full_name.startswith("??_7") or "_ZTV" in full_name:
                    entry_ea = ea
                    for idx in range(100):
                        ptr = _read_ptr(bv, entry_ea)
                        if ptr == 0:
                            break
                        tf = bv.get_functions_at(ptr)
                        if tf:
                            f.write(f"    [{idx}] {ptr:0{aw}X} -> {func_name(tf[0])}\n")
                            entry_ea += ps
                        else:
                            break

            f.write(f"\nTotal RTTI/vtable entries: {len(vtables)}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ VTables DONE: {len(vtables)} → {filepath}")


class DumpAllStructuresTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Collecting structures...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_STRUCTURES.txt")
        count = 0

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL STRUCTURES / TYPES DUMP\n")
            f.write("=" * 80 + "\n\n")

            for type_name, t in bv.types.items():
                if self.cancelled:
                    break
                if hasattr(t, 'structure') and t.structure is not None:
                    count += 1
                    struct = t.structure
                    kind = "UNION" if struct.union else "STRUCT"
                    f.write(f"\n[{kind}] {type_name} (size: {struct.width} bytes)\n")
                    f.write("-" * 60 + "\n")
                    for member in struct.members:
                        mname = member.name or f"field_{member.offset:X}"
                        mtype = str(member.type) if member.type else "?"
                        msize = member.type.width if member.type else 0
                        f.write(f"  +0x{member.offset:04X} {mname} : {mtype} ({msize} bytes)\n")
                elif hasattr(t, 'enumeration') and t.enumeration is not None:
                    count += 1
                    enum = t.enumeration
                    f.write(f"\n[ENUM] {type_name}\n" + "-" * 60 + "\n")
                    for member in enum.members:
                        f.write(f"  {member.name} = {member.value}\n")

            f.write(f"\nTotal types: {count}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ Structures DONE: {count} → {filepath}")


class DumpAllRTTITask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Scanning for RTTI...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        outdir = ensure_output_dir(bv)
        filepath = os.path.join(outdir, "ALL_RTTI.txt")
        aw = _addr_w(bv)
        classes: Dict[str, Dict] = {}
        count = 0

        for sym in bv.get_symbols():
            if self.cancelled:
                break
            count += 1
            name = sym.full_name or sym.raw_name or ""
            ea = sym.address

            if ".?AV" in name or ".?AU" in name:
                m = re.search(r'\.?\?A[VU](.+?)@@', name)
                if m:
                    cn = m.group(1).replace("@", "::")
                    classes.setdefault(cn, {"type_desc": [], "vtables": [], "base_classes": []})
                    classes[cn]["type_desc"].append(ea)
            elif "??_R1" in name:
                m = re.search(r'\?\?_R1.+?@(.+?)@@', name)
                if m:
                    cn = m.group(1).replace("@", "::")
                    classes.setdefault(cn, {"type_desc": [], "vtables": [], "base_classes": []})
                    classes[cn]["base_classes"].append((ea, name))
            elif name.startswith("??_7"):
                m = re.search(r'\?\?_7(.+?)@@', name)
                if m:
                    cn = m.group(1).replace("@", "::")
                    classes.setdefault(cn, {"type_desc": [], "vtables": [], "base_classes": []})
                    classes[cn]["vtables"].append(ea)
            elif "_ZTI" in name:
                classes.setdefault(name, {"type_desc": [], "vtables": [], "base_classes": []})
                classes[name]["type_desc"].append(ea)
            elif "_ZTV" in name:
                classes.setdefault(name, {"type_desc": [], "vtables": [], "base_classes": []})
                classes[name]["vtables"].append(ea)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL RTTI DUMP (C++ Class Information)\n")
            f.write("=" * 80 + "\n\n")
            for cn in sorted(classes.keys()):
                info = classes[cn]
                f.write(f"\n[CLASS] {cn}\n" + "-" * 60 + "\n")
                if info["type_desc"]:
                    f.write("  Type Descriptors:\n")
                    for ea in info["type_desc"]:
                        f.write(f"    {ea:0{aw}X}\n")
                if info["vtables"]:
                    f.write("  VTables:\n")
                    for ea in info["vtables"]:
                        f.write(f"    {ea:0{aw}X}\n")
                if info["base_classes"]:
                    f.write("  Base Class Info:\n")
                    for ea, bn_ in info["base_classes"]:
                        f.write(f"    {ea:0{aw}X} {bn_}\n")
            f.write(f"\nTotal classes: {len(classes)}\n")

        log_info(f"[{PLUGIN_NAME}] ✓ RTTI DONE: {len(classes)} classes → {filepath}")


# ============================================================================
# SINGLE FUNCTION DUMPS
# ============================================================================

def dump_function_assembly(bv: BinaryView, func: Function):
    name = func_name(func)
    safe = sanitize_filename(name)
    outdir = ensure_output_dir(bv, "function_dumps")
    filepath = os.path.join(outdir, f"{safe}.asm")
    asm = get_function_assembly(bv, func)
    if asm:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(asm)
        log_info(f"[{PLUGIN_NAME}] Assembly for {name} → {filepath}")


def dump_function_decompiled(bv: BinaryView, func: Function):
    name = func_name(func)
    safe = sanitize_filename(name)
    outdir = ensure_output_dir(bv, "function_dumps")
    filepath = os.path.join(outdir, f"{safe}.c")
    decompiled = get_function_decompiled(bv, func)
    if decompiled:
        header = f"// Function: {name}\n// Address: 0x{func.start:X}\n\n"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(header + decompiled)
        log_info(f"[{PLUGIN_NAME}] Decompiled for {name} → {filepath}")


def dump_function_xrefs(bv: BinaryView, func: Function):
    name = func_name(func)
    safe = sanitize_filename(name)
    outdir = ensure_output_dir(bv, "function_xrefs")
    filepath = os.path.join(outdir, f"{safe}_xrefs.txt")

    lines = ["=" * 80, f"XREFS FOR: {name}", f"Address: 0x{func.start:X}", "=" * 80, ""]

    # Strings
    str_refs = _get_func_string_refs(bv, func)
    if str_refs:
        lines += ["[STRINGS]", "-" * 40]
        for addr, s in str_refs:
            lines.append(f'  {addr:016X}  "{s}"')
        lines += [f"Total strings: {len(str_refs)}", ""]

    # Callers
    lines += ["[CALLED BY]", "-" * 40]
    callers = set()
    for ref in bv.get_code_refs(func.start):
        for cf in bv.get_functions_containing(ref.address):
            callers.add((cf.start, func_name(cf)))
    for addr, cn in sorted(callers):
        lines.append(f"  {addr:016X}  {cn}")
    lines += [f"Total callers: {len(callers)}", ""]

    # Callees
    lines += ["[CALLS]", "-" * 40]
    callees = set()
    for callee in func.callees:
        callees.add((callee.start, func_name(callee)))
    for addr, cn in sorted(callees):
        lines.append(f"  {addr:016X}  {cn}")
    lines.append(f"Total calls: {len(callees)}")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log_info(f"[{PLUGIN_NAME}] Xrefs for {name} → {filepath}")


def dump_function_full(bv: BinaryView, func: Function):
    """Dump EVERYTHING for a single function: asm + decompiled + IL pipeline + xrefs."""
    name = func_name(func)
    safe = sanitize_filename(name)
    outdir = ensure_output_dir(bv, "function_dumps")
    filepath = os.path.join(outdir, f"{safe}_full.txt")

    lines = ["=" * 80, f"FULL DUMP: {name}", f"Address: 0x{func.start:X}", "=" * 80, ""]

    # Metadata
    cc = func.calling_convention
    lines.append(f"Calling Convention: {cc.name if cc else 'unknown'}")
    lines.append(f"Return Type: {func.return_type or 'void'}")
    lines.append(f"Size: {func.total_bytes} bytes")
    lines.append(f"Basic Blocks: {len(list(func.basic_blocks))}")

    params = func.parameter_vars
    if params:
        lines.append(f"Parameters:")
        for p in params:
            lines.append(f"  {p.type or '?'} {p.name}")

    stack_vars = [v for v in func.vars if v.source_type == bn.VariableSourceType.StackVariableSourceType]
    if stack_vars:
        lines.append(f"Stack Variables:")
        for v in sorted(stack_vars, key=lambda x: x.storage):
            lines.append(f"  [{v.storage:#06x}] {v.type or '?'} {v.name}")
    lines.append("")

    # Assembly
    lines += ["=" * 35 + " ASSEMBLY " + "=" * 35]
    asm = get_function_assembly(bv, func)
    lines.append(asm if asm else "; Failed to get assembly")
    lines.append("")

    # Decompiled
    lines += ["=" * 35 + " DECOMPILED (HLIL) " + "=" * 35]
    decompiled = get_function_decompiled(bv, func)
    lines.append(decompiled if decompiled else "// Decompilation not available")
    lines.append("")

    # IL Pipeline
    lines += ["=" * 35 + " IL PIPELINE " + "=" * 35]
    il = get_function_il_pipeline(bv, func)
    lines.append(il if il else "// IL not available")
    lines.append("")

    # Strings
    lines += ["=" * 35 + " STRINGS " + "=" * 35]
    str_refs = _get_func_string_refs(bv, func)
    if str_refs:
        for addr, s in str_refs:
            lines.append(f'  {addr:016X}  "{s}"')
    else:
        lines.append("  (no strings found)")
    lines.append("")

    # Xrefs
    lines += ["=" * 35 + " XREFS " + "=" * 35, "\n[CALLED BY]"]
    for ref in bv.get_code_refs(func.start):
        for cf in bv.get_functions_containing(ref.address):
            lines.append(f"  {cf.start:016X}  {func_name(cf)}")
    lines.append("\n[CALLS]")
    for callee in func.callees:
        lines.append(f"  {callee.start:016X}  {func_name(callee)}")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log_info(f"[{PLUGIN_NAME}] Full dump for {name} → {filepath}")


def dump_function_il(bv: BinaryView, func: Function):
    """Dump the IL pipeline for a single function."""
    name = func_name(func)
    safe = sanitize_filename(name)
    outdir = ensure_output_dir(bv, "function_dumps")
    filepath = os.path.join(outdir, f"{safe}_il.txt")

    il = get_function_il_pipeline(bv, func)
    if il:
        header = f"// Function: {name}\n// Address: 0x{func.start:X}\n// IL Pipeline: LLIL → MLIL → MLIL-SSA → HLIL\n\n"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(header + il)
        log_info(f"[{PLUGIN_NAME}] IL for {name} → {filepath}")


# ============================================================================
# DUMP EVERYTHING — ALL OF IT
# ============================================================================

# Expected output files for each dump task — used to skip re-dumping
_TASK_OUTPUT_FILES = {
    "Overview":          "ALL_OVERVIEW.txt",
    "Assembly":          "ALL_ASSEMBLY.asm",
    "Decompiled":        "ALL_DECOMPILED.c",
    "IL Pipeline":       "ALL_IL_PIPELINE.txt",
    "Strings":           "ALL_STRINGS.txt",
    "Names":             "ALL_NAMES.txt",
    "Imports":           "ALL_IMPORTS.txt",
    "Exports":           "ALL_EXPORTS.txt",
    "Segments":          "ALL_SEGMENTS.txt",
    "Xrefs":             "ALL_XREFS.txt",
    "Function Details":  "ALL_FUNCTIONS_DETAIL.txt",
    "Call Graph":        "ALL_CALL_GRAPH.txt",
    "String Xrefs":      "ALL_STRING_XREFS.txt",
    "Data Variables":    "ALL_DATA_VARIABLES.txt",
    "Comments/Tags":     "ALL_COMMENTS_TAGS.txt",
    "Structures":        "ALL_STRUCTURES.txt",
    "Full Types":        "ALL_TYPES.txt",
    "RTTI":              "ALL_RTTI.txt",
    "VTables":           "ALL_VTABLES.txt",
}


def _dump_file_is_valid(outdir: str, filename: str, bv: BinaryView) -> bool:
    """Check if a dump file already exists and looks complete.
    For function-based dumps (asm, decompiled), verify the function count matches."""
    filepath = os.path.join(outdir, filename)
    if not os.path.isfile(filepath):
        return False
    try:
        size = os.path.getsize(filepath)
        if size < 100:  # trivially small = incomplete
            return False
    except Exception:
        return False
    # For function-count-sensitive dumps, check the summary line
    if filename in ("ALL_ASSEMBLY.asm", "ALL_DECOMPILED.c"):
        total_funcs = len(list(bv.functions))
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                # Read last 500 bytes for summary line
                f.seek(max(0, size - 500))
                tail = f.read()
                # Look for "Total functions: NNN" or "N decompiled" or "N/M functions"
                import re as _re
                m = _re.search(r'Total functions:\s*(\d+)', tail)
                if m:
                    dumped = int(m.group(1))
                    if dumped == total_funcs:
                        return True
                    return False  # count mismatch
                m = _re.search(r'(\d+)\s+decompiled', tail)
                if m:
                    # Decompiled file — check decompiled+failed = total
                    m2 = _re.search(r'(\d+)\s+failed', tail)
                    if m2:
                        done = int(m.group(1)) + int(m2.group(1))
                        if done == total_funcs:
                            return True
                    return False
                m = _re.search(r'(\d+)/(\d+)\s+functions', tail)
                if m and int(m.group(2)) == total_funcs:
                    return True
                # Can't verify count — file exists and is non-trivial, accept it
                return True
        except Exception:
            return True  # file exists, can't verify, accept it
    return True  # non-function file, exists and non-trivial


class DumpEverythingTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Dumping EVERYTHING...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        log_info(f"[{PLUGIN_NAME}] === DUMPING EVERYTHING ===")

        tasks = [
            # === MOST IMPORTANT — dump these first ===
            ("Overview",        DumpBinaryOverviewTask),
            ("Assembly",        DumpAllAssemblyTask),
            ("Decompiled",      DumpAllDecompiledTask),
            ("IL Pipeline",     DumpAllILPipelineTask),
            # === Core metadata ===
            ("Strings",         DumpAllStringsTask),
            ("Names",           DumpAllNamesTask),
            ("Imports",         DumpAllImportsTask),
            ("Exports",         DumpAllExportsTask),
            ("Segments",        DumpAllSegmentsTask),
            ("Xrefs",           DumpAllXrefsTask),
            # === Rich analysis data ===
            ("Function Details", DumpAllFunctionDetailsTask),
            ("Call Graph",      DumpAllCallGraphTask),
            ("String Xrefs",    DumpAllStringXrefsTask),
            ("Data Variables",  DumpAllDataVariablesTask),
            ("Comments/Tags",   DumpAllCommentsAndTagsTask),
            # === Type system ===
            ("Structures",      DumpAllStructuresTask),
            ("Full Types",      DumpAllTypesTask),
            ("RTTI",            DumpAllRTTITask),
            ("VTables",         DumpAllVTablesTask),
        ]

        outdir = ensure_output_dir(bv)
        failed = []
        skipped = []
        total_tasks = len(tasks)
        for task_idx, (name, task_cls) in enumerate(tasks, 1):
            if self.cancelled:
                break
            # Check if this dump already exists and is complete
            expected_file = _TASK_OUTPUT_FILES.get(name)
            if expected_file and _dump_file_is_valid(outdir, expected_file, bv):
                log_info(f"[{PLUGIN_NAME}] ═══ [{task_idx}/{total_tasks}] SKIP: {name} — {expected_file} already exists and is complete ═══")
                skipped.append(name)
                continue
            self.progress = f"[{task_idx}/{total_tasks}] Dumping {name}..."
            log_info(f"[{PLUGIN_NAME}] ═══ [{task_idx}/{total_tasks}] Starting: {name} ═══")
            try:
                t = task_cls(bv)
                t.run()
            except Exception as e:
                log_error(f"[{PLUGIN_NAME}] ✗ ERROR dumping {name}: {e}")
                traceback.print_exc()
                failed.append(name)

        dumped = total_tasks - len(failed) - len(skipped)
        summary = f"Dumped: {dumped}, Skipped (existing): {len(skipped)}, Failed: {len(failed)}"
        if failed:
            log_info(f"[{PLUGIN_NAME}] === COMPLETE — {summary} (errors: {', '.join(failed)}) ===")
        else:
            log_info(f"[{PLUGIN_NAME}] === COMPLETE — {summary} ===")

        interaction.show_message_box(
            PLUGIN_NAME,
            f"Dump complete!\n{summary}\n\n"
            f"Output: {outdir}"
            + (f"\n\nSkipped: {', '.join(skipped)}" if skipped else "")
            + (f"\n\nFailed: {', '.join(failed)}" if failed else ""),
        )


# ============================================================================
# CLIPBOARD COPY ACTIONS
# ============================================================================

def copy_function_assembly(bv: BinaryView, func: Function):
    asm = get_function_assembly(bv, func)
    if asm:
        _set_clipboard(asm)
        log_info(f"[{PLUGIN_NAME}] Copied assembly for {func_name(func)}")


def copy_function_decompiled(bv: BinaryView, func: Function):
    name = func_name(func)
    decompiled = get_function_decompiled(bv, func)
    if decompiled:
        header = f"// Function: {name}\n// Address: 0x{func.start:X}\n\n"
        _set_clipboard(header + decompiled)
        log_info(f"[{PLUGIN_NAME}] Copied decompiled for {name}")


def copy_function_all(bv: BinaryView, func: Function):
    name = func_name(func)
    parts = ["=" * 80, f"FUNCTION: {name} (0x{func.start:X})", "=" * 80, ""]
    parts += ["-" * 40 + " ASSEMBLY " + "-" * 40]
    asm = get_function_assembly(bv, func)
    parts.append(asm if asm else "; Failed")
    parts += ["", "-" * 40 + " DECOMPILED " + "-" * 40]
    decompiled = get_function_decompiled(bv, func)
    parts.append(decompiled if decompiled else "// Failed")
    parts += ["", "-" * 40 + " IL PIPELINE " + "-" * 40]
    il = get_function_il_pipeline(bv, func)
    parts.append(il if il else "// IL not available")
    _set_clipboard("\n".join(parts))
    log_info(f"[{PLUGIN_NAME}] Copied ALL for {name}")


# ============================================================================
# PLUGIN REGISTRATION
# ============================================================================

def _reg(suffix, desc, task_cls):
    def launcher(bv):
        task_cls(bv).start()
    PluginCommand.register(f"{PLUGIN_NAME}\\{suffix}", desc, launcher)

# BinaryView-level commands
_reg("Dump ALL Assembly (.asm)",    "Dump all functions as assembly",                 DumpAllAssemblyTask)
_reg("Dump ALL Decompiled (.c)",    "Dump all functions as decompiled C (HLIL)",       DumpAllDecompiledTask)
_reg("Dump ALL Strings",           "Dump all strings",                                DumpAllStringsTask)
_reg("Dump ALL String Xrefs",      "Dump string→function xref map",                  DumpAllStringXrefsTask)
_reg("Dump ALL Names",             "Dump all named symbols",                          DumpAllNamesTask)
_reg("Dump ALL Imports",           "Dump all imports",                                DumpAllImportsTask)
_reg("Dump ALL Exports",           "Dump all exports",                                DumpAllExportsTask)
_reg("Dump ALL Segments",          "Dump all sections/segments",                      DumpAllSegmentsTask)
_reg("Dump ALL Data Variables",    "Dump all global/static data with types",          DumpAllDataVariablesTask)
_reg("Dump ALL VTables",           "Dump all virtual function tables",                DumpAllVTablesTask)
_reg("Dump ALL RTTI",              "Dump all RTTI class info",                        DumpAllRTTITask)
_reg("Dump ALL Xrefs",             "Dump all cross-references",                      DumpAllXrefsTask)
_reg("Dump ALL Structures",        "Dump structs/enums/unions",                       DumpAllStructuresTask)
_reg("Dump ALL Types (Full)",      "Dump complete type library",                      DumpAllTypesTask)
_reg("Dump ALL Function Details",  "Dump rich per-function metadata",                DumpAllFunctionDetailsTask)
_reg("Dump ALL Call Graph",        "Dump complete call graph",                        DumpAllCallGraphTask)
_reg("Dump ALL Comments & Tags",   "Dump all comments, tags, bookmarks",             DumpAllCommentsAndTagsTask)
_reg("Dump ALL IL Pipeline",       "Dump LLIL→MLIL→HLIL for all functions",          DumpAllILPipelineTask)
_reg("Dump Binary Overview",       "Dump binary metadata/triage info",               DumpBinaryOverviewTask)
_reg("Dump EVERYTHING",            "Run ALL 19 dumps at once",                       DumpEverythingTask)

# Function-level commands (right-click on function)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Copy Assembly",            "Copy assembly to clipboard",           copy_function_assembly)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Copy Decompiled",          "Copy decompiled to clipboard",         copy_function_decompiled)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Copy ALL (Asm+Dec+IL)",    "Copy asm + decompiled + IL pipeline",  copy_function_all)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Dump Function Assembly",   "Save assembly to file",                dump_function_assembly)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Dump Function Decompiled", "Save decompiled to file",              dump_function_decompiled)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Dump Function Xrefs",      "Save xrefs to file",                  dump_function_xrefs)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Dump Function IL Pipeline","Save LLIL→MLIL→HLIL to file",          dump_function_il)
PluginCommand.register_for_function(f"{PLUGIN_NAME}\\Dump Function (Full)",     "Save everything for this function",    dump_function_full)

log_info(f"[{PLUGIN_NAME}] Loaded! 19 dump categories available via Plugins menu or right-click.")
