
# IDA Pro 9.2 plugin — Dump EVERYTHING from the database
# Dumps: Assembly, Decompiled, Strings, Names, Imports, Exports, Segments,
#         VTables, RTTI, Xrefs, Structures, Overview, Function Details,
#         Call Graph, String Xrefs, Data Variables, Comments, Full Types,
#         Problems, Try/Catch, Fixups, Patched Bytes, Hidden Ranges,
#         Bookmarks, Switch Tables
from __future__ import print_function
import os, re, traceback, time

import idaapi
import idc
import idautils
import ida_funcs
import ida_kernwin
import ida_bytes
import ida_nalt
import ida_ida
import ida_segment
import ida_typeinf
import ida_lines
import ida_loader
import ida_xref
import ida_gdl
import ida_problems
import ida_fixup
import ida_frame

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None

try:
    import ida_tryblks
except Exception:
    ida_tryblks = None

try:
    import ida_moves
except Exception:
    ida_moves = None

PLUGIN_NAME = "Ida Dumper"
OUTPUT_DIR_NAME = "IDA_DUMPS"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def sanitize_filename(name: str) -> str:
    return re.sub(r'[^0-9A-Za-z._-]', '_', name)

def ensure_output_dir(subdir=None):
    input_path = idaapi.get_input_file_path() or ""
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

def log_info(msg):
    idaapi.msg(f"[{PLUGIN_NAME}] {msg}\n")

def log_progress(task_name, current, total):
    if total > 0:
        pct = current * 100 // total
        log_info(f"  [{task_name}] {pct}% ({current}/{total})")

def _hexrays_ready():
    if ida_hexrays is None:
        return False
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False

def _pseudocode_text(cf) -> str:
    out = []
    for ln in cf.get_pseudocode():
        try:
            s = str(ln.line)
        except Exception:
            s = str(ln)
        s = ida_lines.tag_remove(s)
        out.append(s)
    return "\n".join(out)

def _is_64bit():
    try:
        return idaapi.inf_is_64bit()
    except Exception:
        return ida_ida.inf_is_64bit()

def _ptr_size():
    return 8 if _is_64bit() else 4

def _read_ptr(ea):
    return idc.get_qword(ea) if _is_64bit() else idc.get_wide_dword(ea)

def get_function_assembly(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    lines = []
    func_name = idc.get_func_name(ea) or f"func_{ea:X}"
    lines.append(f"; Function: {func_name}")
    lines.append(f"; Address: 0x{ea:X} - 0x{func.end_ea:X}")
    lines.append(f"; Size: {func.end_ea - ea} bytes")
    lines.append("")
    current_ea = func.start_ea
    while current_ea < func.end_ea:
        for i in range(1000):
            anterior = idc.get_extra_cmt(current_ea, idc.E_PREV + i)
            if anterior:
                lines.append(f"; {anterior}")
            else:
                break
        disasm = idc.generate_disasm_line(current_ea, idc.GENDSM_FORCE_CODE)
        if disasm:
            disasm = ida_lines.tag_remove(disasm)
            addr_str = f".text:{current_ea:016X}"
            cmt = idc.get_cmt(current_ea, 0)
            rep_cmt = idc.get_cmt(current_ea, 1)
            line = f"{addr_str}    {disasm}"
            if rep_cmt and rep_cmt not in disasm:
                line += f"    ; {rep_cmt}"
            elif cmt and cmt not in disasm:
                line += f"    ; {cmt}"
            lines.append(line)
        for i in range(1000):
            posterior = idc.get_extra_cmt(current_ea, idc.E_NEXT + i)
            if posterior:
                lines.append(f"; {posterior}")
            else:
                break
        current_ea = idc.next_head(current_ea, func.end_ea)
        if current_ea == idaapi.BADADDR:
            break
    return "\n".join(lines)

def get_function_decompiled(ea):
    if not _hexrays_ready():
        return None
    try:
        cf = ida_hexrays.decompile(ea)
        if not cf:
            return None
        return _pseudocode_text(cf)
    except Exception:
        return None

def get_function_strings(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    strings = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head):
            str_type = idc.get_str_type(xref.to)
            if str_type is not None and str_type >= 0:
                content = idc.get_strlit_contents(xref.to, -1, str_type)
                if content:
                    if isinstance(content, bytes):
                        try:
                            content = content.decode('utf-8', errors='replace')
                        except Exception:
                            content = content.decode('latin-1', errors='replace')
                    strings.append((xref.to, content))
    seen = set()
    unique = []
    for addr, s in strings:
        if addr not in seen:
            seen.add(addr)
            unique.append((addr, s))
    return unique

def copy_to_clipboard(text):
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = wintypes.BOOL
        user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        user32.SetClipboardData.restype = wintypes.HANDLE
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = wintypes.LPVOID
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.restype = wintypes.BOOL
        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        GMEM_ZEROINIT = 0x0040
        if isinstance(text, str):
            data = text.encode('utf-16le') + b'\x00\x00'
        else:
            data = str(text).encode('utf-16le') + b'\x00\x00'
        if not user32.OpenClipboard(None):
            log_info("Failed to open clipboard")
            return False
        try:
            user32.EmptyClipboard()
            hMem = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data))
            if not hMem:
                return False
            pMem = kernel32.GlobalLock(hMem)
            if not pMem:
                return False
            ctypes.memmove(pMem, data, len(data))
            kernel32.GlobalUnlock(hMem)
            if not user32.SetClipboardData(CF_UNICODETEXT, hMem):
                return False
            return True
        finally:
            user32.CloseClipboard()
    except Exception as e:
        log_info(f"Clipboard error: {e}")
        return False

# ============================================================================
# 1. DUMP ALL ASSEMBLY
# ============================================================================

def dump_all_assembly():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_ASSEMBLY.asm")
    log_info(f"=== [1/25] ASSEMBLY === Dumping to: {filepath}")
    func_list = list(idautils.Functions())
    total = len(func_list)
    success = 0
    ida_kernwin.show_wait_box(f"Dumping assembly... 0/{total}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(";" + "=" * 79 + "\n")
            f.write("; ALL ASSEMBLY DUMP\n")
            f.write(f"; Total functions: {total}\n")
            f.write(";" + "=" * 79 + "\n\n")
            for i, func_ea in enumerate(func_list):
                if ida_kernwin.user_cancelled():
                    log_info("Cancelled by user"); break
                if i % 100 == 0:
                    ida_kernwin.replace_wait_box(f"Dumping assembly... {i}/{total}")
                if i % 500 == 0 and i > 0:
                    log_progress("Assembly", i, total)
                asm = get_function_assembly(func_ea)
                if asm:
                    f.write(";" + "-" * 79 + "\n")
                    f.write(asm)
                    f.write("\n\n")
                    success += 1
            f.write(f"\n; Dump complete: {success}/{total} functions\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Assembly dump complete: {success}/{total} functions -> {filepath}")

# ============================================================================
# 2. DUMP ALL DECOMPILED
# ============================================================================

def dump_all_decompiled():
    if not _hexrays_ready():
        log_info("Hex-Rays decompiler not available!")
        return
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_DECOMPILED.c")
    log_info(f"=== [2/25] DECOMPILED === Dumping to: {filepath}")
    func_list = list(idautils.Functions())
    total = len(func_list)
    success = failed = 0
    ida_kernwin.show_wait_box(f"Decompiling... 0/{total}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("/" + "*" * 78 + "/\n")
            f.write("/* ALL DECOMPILED DUMP */\n")
            f.write("/* ONLY decompiled pseudocode — failed functions are SKIPPED */\n")
            f.write("/* Assembly for all functions (including failed) is in ALL_ASSEMBLY.asm */\n")
            f.write(f"/* Total functions: {total} */\n")
            f.write("/" + "*" * 78 + "/\n\n")
            for i, func_ea in enumerate(func_list):
                if ida_kernwin.user_cancelled():
                    log_info("Cancelled by user"); break
                if i % 100 == 0:
                    ida_kernwin.replace_wait_box(f"Decompiling... {i}/{total} ({success} ok, {failed} failed)")
                if i % 500 == 0 and i > 0:
                    log_progress("Decompiled", i, total)
                func_name = idc.get_func_name(func_ea) or f"func_{func_ea:X}"
                try:
                    decompiled = get_function_decompiled(func_ea)
                    if decompiled:
                        # String refs comment
                        func_strings = get_function_strings(func_ea)
                        f.write("/" + "-" * 78 + "/\n")
                        f.write(f"// Function: {func_name}\n")
                        f.write(f"// Address: 0x{func_ea:X}\n")
                        if func_strings:
                            f.write("// Strings referenced:\n")
                            for saddr, scontent in func_strings:
                                s_esc = scontent.replace('\n', '\\n').replace('\r', '\\r')
                                f.write(f"//   0x{saddr:X}: \"{s_esc}\"\n")
                        f.write("\n")
                        f.write(decompiled)
                        f.write("\n\n")
                        success += 1
                    else:
                        failed += 1
                except Exception:
                    failed += 1
            f.write(f"\n/* Dump complete: {success} decompiled, {failed} failed out of {total} */\n")
            f.write(f"/* Failed functions are NOT included — check ALL_ASSEMBLY.asm for those */\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Decompiled dump complete: {success} ok, {failed} failed / {total} total -> {filepath}")

# ============================================================================
# 3. DUMP BINARY OVERVIEW
# ============================================================================

def dump_binary_overview():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_OVERVIEW.txt")
    log_info(f"=== [3/25] OVERVIEW === Dumping to: {filepath}")
    lines = []
    lines.append("=" * 80)
    lines.append("BINARY OVERVIEW")
    lines.append("=" * 80)
    lines.append("")
    input_path = idaapi.get_input_file_path() or "(unknown)"
    lines.append(f"Input file: {input_path}")
    lines.append(f"Binary name: {os.path.basename(input_path)}")
    try:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        lines.append(f"IDB path: {idb_path}")
    except Exception:
        pass
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        if md5:
            lines.append(f"MD5: {md5.hex() if isinstance(md5, bytes) else md5}")
    except Exception:
        pass
    try:
        sha256 = ida_nalt.retrieve_input_file_sha256()
        if sha256:
            lines.append(f"SHA256: {sha256.hex() if isinstance(sha256, bytes) else sha256}")
    except Exception:
        pass
    lines.append("")
    lines.append("[ARCHITECTURE]")
    lines.append("-" * 40)
    try:
        lines.append(f"Processor: {ida_ida.inf_get_procname()}")
    except Exception:
        pass
    lines.append(f"64-bit: {_is_64bit()}")
    try:
        lines.append(f"Min address: 0x{ida_ida.inf_get_min_ea():X}")
        lines.append(f"Max address: 0x{ida_ida.inf_get_max_ea():X}")
    except Exception:
        pass
    try:
        lines.append(f"File type: {ida_loader.get_file_type_name()}")
    except Exception:
        pass
    lines.append("")
    lines.append("[STATISTICS]")
    lines.append("-" * 40)
    func_list = list(idautils.Functions())
    lines.append(f"Total functions: {len(func_list)}")
    lines.append(f"Total names: {sum(1 for _ in idautils.Names())}")
    lines.append(f"Total strings: {sum(1 for _ in idautils.Strings())}")
    lines.append(f"Total segments: {sum(1 for _ in idautils.Segments())}")
    import_count = 0
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        def _cnt(ea, name, ordinal):
            nonlocal import_count
            import_count += 1
            return True
        ida_nalt.enum_import_names(i, _cnt)
    lines.append(f"Total imports: {import_count} from {nimps} modules")
    lines.append(f"Total exports/entries: {sum(1 for _ in idautils.Entries())}")
    lines.append("")
    lines.append("[SEGMENTS]")
    lines.append("-" * 40)
    lines.append(f"{'Name':<20} {'Start':>18} {'End':>18} {'Size':>12} {'Class':<10} {'Perms'}")
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            name = idc.get_segm_name(seg_ea) or "?"
            perms = ""
            if seg.perm & idaapi.SEGPERM_READ: perms += "R"
            if seg.perm & idaapi.SEGPERM_WRITE: perms += "W"
            if seg.perm & idaapi.SEGPERM_EXEC: perms += "X"
            lines.append(f"{name:<20} {seg.start_ea:018X} {seg.end_ea:018X} {seg.end_ea - seg.start_ea:>12} {idaapi.get_segm_class(seg) or '':<10} {perms}")
    lines.append("")
    lines.append("[ENTRY POINTS]")
    lines.append("-" * 40)
    for idx, ordinal, ea, name in idautils.Entries():
        lines.append(f"  {ea:016X}  ord:{ordinal}  {name}")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log_info(f"Overview dump complete -> {filepath}")

# ============================================================================
# 4. DUMP ALL FUNCTION DETAILS
# ============================================================================

def dump_all_function_details():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_FUNCTION_DETAILS.txt")
    log_info(f"=== [4/25] FUNCTION DETAILS === Dumping to: {filepath}")
    func_list = list(idautils.Functions())
    total = len(func_list)
    count = 0
    ida_kernwin.show_wait_box(f"Dumping function details... 0/{total}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL FUNCTION DETAILS\n")
            f.write(f"Total functions: {total}\n")
            f.write("=" * 80 + "\n\n")
            for i, func_ea in enumerate(func_list):
                if ida_kernwin.user_cancelled():
                    log_info("Cancelled by user"); break
                if i % 200 == 0:
                    ida_kernwin.replace_wait_box(f"Function details... {i}/{total}")
                if i % 1000 == 0 and i > 0:
                    log_progress("FuncDetails", i, total)
                pfn = ida_funcs.get_func(func_ea)
                if not pfn:
                    continue
                count += 1
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                f.write(f"\n[FUNC] {func_name}\n")
                f.write("-" * 60 + "\n")
                f.write(f"  Address: 0x{func_ea:X} - 0x{pfn.end_ea:X}\n")
                f.write(f"  Size: {pfn.end_ea - func_ea} bytes\n")
                f.write(f"  Flags: 0x{pfn.flags:08X}")
                flag_descs = []
                if pfn.flags & ida_funcs.FUNC_NORET: flag_descs.append("NORET")
                if pfn.flags & ida_funcs.FUNC_FAR: flag_descs.append("FAR")
                if pfn.flags & ida_funcs.FUNC_FRAME: flag_descs.append("FRAME")
                if pfn.flags & ida_funcs.FUNC_THUNK: flag_descs.append("THUNK")
                try:
                    if pfn.flags & ida_funcs.FUNC_LUMINA: flag_descs.append("LUMINA")
                except Exception: pass
                try:
                    if pfn.flags & ida_funcs.FUNC_OUTLINE: flag_descs.append("OUTLINE")
                except Exception: pass
                if flag_descs:
                    f.write(f" ({', '.join(flag_descs)})")
                f.write("\n")
                # Frame info
                if ida_funcs.is_func_entry(pfn):
                    f.write(f"  Frame ID: 0x{pfn.frame:X}\n")
                    f.write(f"  Local vars size: 0x{pfn.frsize:X}\n")
                    f.write(f"  Saved regs size: 0x{pfn.frregs:X}\n")
                    f.write(f"  Args size: 0x{pfn.argsize:X}\n")
                    try:
                        f.write(f"  FP delta: 0x{pfn.fpd:X}\n")
                    except Exception: pass
                    # Stack frame members
                    try:
                        frame_tif = pfn.frame_object
                        if frame_tif:
                            f.write(f"  Frame size: 0x{frame_tif.get_size():X}\n")
                            f.write("  Frame members:\n")
                            for idx, udm in enumerate(frame_tif.iter_struct()):
                                f.write(f"    +0x{udm.offset // 8:04X} {udm.name}: {udm.type.dstr()}\n")
                    except Exception: pass
                    # Register variables
                    try:
                        if pfn.regvarqty > 0:
                            f.write(f"  Register vars ({pfn.regvarqty}):\n")
                            for rv in pfn.regvars:
                                f.write(f"    0x{rv.start_ea:X}..0x{rv.end_ea:X}  '{rv.canon}' -> '{rv.user}'\n")
                    except Exception: pass
                    # Register arguments
                    try:
                        if pfn.regargqty > 0:
                            f.write(f"  Register args ({pfn.regargqty}):\n")
                            for ra in pfn.regargs:
                                f.write(f"    reg#{ra.reg}  name=\"{ra.name}\"\n")
                    except Exception: pass
                    # Stack change points
                    try:
                        if pfn.pntqty > 0:
                            f.write(f"  Stack points ({pfn.pntqty}):\n")
                            for pi in range(pfn.pntqty):
                                pnt = pfn.points[pi]
                                f.write(f"    @0x{pnt.ea:X}: spd={pnt.spd}\n")
                    except Exception: pass
                    # Tail chunks
                    try:
                        if pfn.tailqty > 0:
                            f.write(f"  Tail chunks ({pfn.tailqty}):\n")
                            for ti in range(pfn.tailqty):
                                tail = pfn.tails[ti]
                                f.write(f"    0x{tail.start_ea:X}..0x{tail.end_ea:X}\n")
                    except Exception: pass
                # Prototype
                try:
                    proto = pfn.prototype
                    if proto:
                        f.write(f"  Returns: {proto.get_rettype()}\n")
                        f.write("  Parameters:\n")
                        for arg in proto.iter_func():
                            f.write(f"    {arg.name}: {arg.type}\n")
                except Exception: pass
                # Function comments
                func_cmt = idc.get_func_cmt(func_ea, 0)
                func_cmt_rep = idc.get_func_cmt(func_ea, 1)
                if func_cmt:
                    f.write(f"  Comment: {func_cmt}\n")
                if func_cmt_rep:
                    f.write(f"  Repeatable comment: {func_cmt_rep}\n")
                # Basic blocks
                try:
                    fc = ida_gdl.FlowChart(pfn)
                    bb_count = sum(1 for _ in fc)
                    f.write(f"  Basic blocks: {bb_count}\n")
                except Exception: pass
                # Strings referenced
                func_strings = get_function_strings(func_ea)
                if func_strings:
                    f.write(f"  Strings referenced ({len(func_strings)}):\n")
                    for saddr, scontent in func_strings:
                        s_esc = scontent.replace('\n', '\\n').replace('\r', '\\r')
                        f.write(f"    0x{saddr:X}: \"{s_esc}\"\n")
            f.write(f"\nTotal functions detailed: {count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Function details dump complete: {count}/{total} -> {filepath}")

# ============================================================================
# 5. DUMP ALL CALL GRAPH
# ============================================================================

def dump_all_call_graph():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_CALL_GRAPH.txt")
    log_info(f"=== [5/25] CALL GRAPH === Dumping to: {filepath}")
    func_list = list(idautils.Functions())
    total = len(func_list)
    edge_count = 0
    ida_kernwin.show_wait_box(f"Building call graph... 0/{total}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL CALL GRAPH\n")
            f.write(f"Total functions: {total}\n")
            f.write("=" * 80 + "\n\n")
            for i, func_ea in enumerate(func_list):
                if ida_kernwin.user_cancelled():
                    log_info("Cancelled by user"); break
                if i % 200 == 0:
                    ida_kernwin.replace_wait_box(f"Call graph... {i}/{total}")
                if i % 1000 == 0 and i > 0:
                    log_progress("CallGraph", i, total)
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue
                callees = set()
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    for xref in idautils.XrefsFrom(head):
                        if xref.type in [idaapi.fl_CF, idaapi.fl_CN]:
                            callees.add(xref.to)
                if callees:
                    f.write(f"[CALLER] {func_name} (0x{func_ea:X})\n")
                    for callee_ea in sorted(callees):
                        callee_name = idc.get_func_name(callee_ea) or f"sub_{callee_ea:X}"
                        f.write(f"  -> {callee_name} (0x{callee_ea:X})\n")
                        edge_count += 1
                    f.write("\n")
            f.write(f"\nTotal edges: {edge_count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Call graph dump complete: {edge_count} edges -> {filepath}")

# ============================================================================
# 6. DUMP ALL STRING XREFS
# ============================================================================

def dump_all_string_xrefs():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_STRING_XREFS.txt")
    log_info(f"=== [6/25] STRING XREFS === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Collecting string xrefs...")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL STRING CROSS-REFERENCES\n")
            f.write("=" * 80 + "\n\n")
            count = 0
            for s in idautils.Strings():
                if count % 1000 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"String xrefs... {count}")
                count += 1
                addr = s.ea
                try:
                    content = idc.get_strlit_contents(addr, s.length, s.strtype)
                    if content:
                        if isinstance(content, bytes):
                            try: content = content.decode('utf-8', errors='replace')
                            except Exception: content = content.decode('latin-1', errors='replace')
                    else:
                        continue
                except Exception:
                    continue
                refs = []
                for xref in idautils.XrefsTo(addr):
                    ref_func = ida_funcs.get_func(xref.frm)
                    if ref_func:
                        rname = idc.get_func_name(ref_func.start_ea) or f"sub_{ref_func.start_ea:X}"
                        refs.append((xref.frm, rname, "CODE"))
                    else:
                        rname = idc.get_name(xref.frm) or f"data_{xref.frm:X}"
                        refs.append((xref.frm, rname, "DATA"))
                s_esc = content.replace('\n', '\\n').replace('\r', '\\r')
                f.write(f"[STRING] 0x{addr:X}: \"{s_esc}\"\n")
                if refs:
                    for raddr, rname, rtype in refs:
                        f.write(f"  <- {rtype} {raddr:016X}  {rname}\n")
                else:
                    f.write("  (no references)\n")
                f.write("\n")
            f.write(f"\nTotal strings: {count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"String xrefs dump complete -> {filepath}")

# ============================================================================
# 7. DUMP ALL DATA VARIABLES
# ============================================================================

def dump_all_data_variables():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_DATA_VARIABLES.txt")
    log_info(f"=== [7/25] DATA VARIABLES === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Collecting data variables...")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL DATA VARIABLES\n")
            f.write("=" * 80 + "\n\n")
            count = 0
            data_count = 0
            for ea, name in idautils.Names():
                if count % 5000 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Data variables... {data_count} found")
                count += 1
                flags = idc.get_full_flags(ea)
                if not idc.is_data(flags):
                    continue
                data_count += 1
                seg_name = idc.get_segm_name(ea) or "?"
                item_size = idc.get_item_size(ea)
                if idc.is_byte(flags): dtype = "BYTE"
                elif idc.is_word(flags): dtype = "WORD"
                elif idc.is_dword(flags): dtype = "DWORD"
                elif idc.is_qword(flags): dtype = "QWORD"
                elif idc.is_float(flags): dtype = "FLOAT"
                elif idc.is_double(flags): dtype = "DOUBLE"
                else: dtype = "DATA"
                value_str = ""
                try:
                    if dtype == "BYTE": value_str = f"= 0x{idc.get_wide_byte(ea):02X}"
                    elif dtype == "WORD": value_str = f"= 0x{idc.get_wide_word(ea):04X}"
                    elif dtype == "DWORD": value_str = f"= 0x{idc.get_wide_dword(ea):08X}"
                    elif dtype == "QWORD": value_str = f"= 0x{idc.get_qword(ea):016X}"
                except Exception: pass
                type_str = ""
                try:
                    tinfo = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tinfo, ea):
                        type_str = tinfo.dstr()
                except Exception: pass
                line = f"{seg_name}:{ea:016X}  {dtype:8s}  size={item_size:<6d}  {name}"
                if type_str: line += f"  type={type_str}"
                if value_str: line += f"  {value_str}"
                cmt = idc.get_cmt(ea, 0)
                rep_cmt = idc.get_cmt(ea, 1)
                if cmt: line += f"  ; {cmt}"
                elif rep_cmt: line += f"  ; {rep_cmt}"
                f.write(line + "\n")
            f.write(f"\nTotal data variables: {data_count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Data variables dump complete: {data_count} -> {filepath}")

# ============================================================================
# 8. DUMP ALL COMMENTS
# ============================================================================

def dump_all_comments():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_COMMENTS.txt")
    log_info(f"=== [8/25] COMMENTS === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Collecting comments...")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL COMMENTS DUMP\n")
            f.write("=" * 80 + "\n\n")
            # Function comments
            f.write("[FUNCTION COMMENTS]\n" + "-" * 60 + "\n")
            func_cmt_count = 0
            for func_ea in idautils.Functions():
                cmt = idc.get_func_cmt(func_ea, 0)
                rep_cmt = idc.get_func_cmt(func_ea, 1)
                if cmt or rep_cmt:
                    func_cmt_count += 1
                    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                    f.write(f"\n{func_name} (0x{func_ea:X}):\n")
                    if cmt: f.write(f"  Comment: {cmt}\n")
                    if rep_cmt: f.write(f"  Repeatable: {rep_cmt}\n")
            f.write(f"\nTotal function comments: {func_cmt_count}\n\n")
            # Address comments
            f.write("[ADDRESS COMMENTS]\n" + "-" * 60 + "\n")
            addr_cmt_count = 0
            min_ea = ida_ida.inf_get_min_ea()
            max_ea = ida_ida.inf_get_max_ea()
            head = idc.next_head(min_ea - 1, max_ea)
            while head != idaapi.BADADDR:
                if addr_cmt_count % 5000 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Comments... {addr_cmt_count} found")
                cmt = idc.get_cmt(head, 0)
                rep_cmt = idc.get_cmt(head, 1)
                anteriors = []
                for ci in range(1000):
                    ac = idc.get_extra_cmt(head, idc.E_PREV + ci)
                    if ac: anteriors.append(ac)
                    else: break
                posteriors = []
                for ci in range(1000):
                    pc = idc.get_extra_cmt(head, idc.E_NEXT + ci)
                    if pc: posteriors.append(pc)
                    else: break
                if cmt or rep_cmt or anteriors or posteriors:
                    addr_cmt_count += 1
                    func_name = idc.get_func_name(head) or ""
                    loc = f"0x{head:X}"
                    if func_name: loc += f" ({func_name})"
                    f.write(f"\n{loc}:\n")
                    for ac in anteriors: f.write(f"  ANTERIOR: {ac}\n")
                    if cmt: f.write(f"  COMMENT: {cmt}\n")
                    if rep_cmt: f.write(f"  REPEATABLE: {rep_cmt}\n")
                    for pc in posteriors: f.write(f"  POSTERIOR: {pc}\n")
                head = idc.next_head(head, max_ea)
            f.write(f"\nTotal address comments: {addr_cmt_count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Comments dump complete -> {filepath}")

# ============================================================================
# 9. DUMP ALL TYPES (structs, enums, typedefs, function types)
# ============================================================================

def dump_all_types():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_TYPES.txt")
    log_info(f"=== [9/25] TYPES === Dumping to: {filepath}")
    til = ida_typeinf.get_idati()
    if not til:
        log_info("ERROR: Could not get type library"); return
    try:
        ordinal_limit = ida_typeinf.get_ordinal_count(til)
    except Exception:
        try:
            ordinal_limit = ida_typeinf.get_ordinal_qty(til)
        except Exception:
            ordinal_limit = 0
    ida_kernwin.show_wait_box(f"Dumping types... 0/{ordinal_limit}")
    struct_count = union_count = enum_count = typedef_count = functype_count = other_count = 0
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL TYPES DUMP (Complete Type Library)\n")
            f.write(f"Total ordinals: {ordinal_limit}\n")
            f.write("=" * 80 + "\n\n")
            for ordinal in range(1, ordinal_limit + 1):
                if ordinal % 100 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Types... {ordinal}/{ordinal_limit}")
                tinfo = ida_typeinf.tinfo_t()
                if not tinfo.get_numbered_type(til, ordinal):
                    continue
                name = tinfo.get_type_name()
                if not name:
                    name = f"type_{ordinal}"
                if tinfo.is_struct() or tinfo.is_union():
                    is_union = tinfo.is_union()
                    if is_union: union_count += 1; kind = "UNION"
                    else: struct_count += 1; kind = "STRUCT"
                    size = tinfo.get_size()
                    f.write(f"\n[{kind}] {name} (ordinal={ordinal}, size={size} bytes)\n")
                    f.write("-" * 60 + "\n")
                    udt = ida_typeinf.udt_type_data_t()
                    if tinfo.get_udt_details(udt):
                        for mi in range(udt.size()):
                            member = udt[mi]
                            mname = member.name if member.name else f"field_{mi}"
                            moff = member.offset // 8
                            msize = member.size // 8
                            mtype_str = member.type.dstr() if member.type else ""
                            if mtype_str:
                                f.write(f"  +0x{moff:04X} {mname} : {mtype_str} ({msize} bytes)\n")
                            else:
                                f.write(f"  +0x{moff:04X} {mname} ({msize} bytes)\n")
                    f.write("\n")
                elif tinfo.is_enum():
                    enum_count += 1
                    f.write(f"\n[ENUM] {name} (ordinal={ordinal})\n")
                    f.write("-" * 60 + "\n")
                    try:
                        for edm in tinfo.iter_enum():
                            f.write(f"  {edm.name} = 0x{edm.value:X}\n")
                    except Exception:
                        try:
                            ed = ida_typeinf.enum_type_data_t()
                            if tinfo.get_enum_details(ed):
                                for ei in range(ed.size()):
                                    em = ed[ei]
                                    f.write(f"  {em.name} = 0x{em.value:X}\n")
                        except Exception:
                            f.write("  (could not enumerate members)\n")
                    f.write("\n")
                elif tinfo.is_typedef():
                    typedef_count += 1
                    f.write(f"[TYPEDEF] {name} = {tinfo.dstr()}  (ordinal={ordinal})\n")
                elif tinfo.is_func():
                    functype_count += 1
                    f.write(f"\n[FUNCTYPE] {name} (ordinal={ordinal})\n")
                    f.write("-" * 60 + "\n")
                    try:
                        fi = ida_typeinf.func_type_data_t()
                        if tinfo.get_func_details(fi):
                            ret_type = fi.rettype.dstr() if fi.rettype else "void"
                            f.write(f"  Returns: {ret_type}\n")
                            f.write(f"  Parameters ({fi.size()}):\n")
                            for pi in range(fi.size()):
                                param = fi[pi]
                                pname = param.name if param.name else f"arg_{pi}"
                                ptype = param.type.dstr() if param.type else "?"
                                f.write(f"    {pname}: {ptype}\n")
                        else:
                            f.write(f"  {tinfo.dstr()}\n")
                    except Exception:
                        f.write(f"  {tinfo.dstr()}\n")
                    f.write("\n")
                else:
                    other_count += 1
                    f.write(f"[TYPE] {name} = {tinfo.dstr()}  (ordinal={ordinal})\n")
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"Structs: {struct_count}\nUnions: {union_count}\nEnums: {enum_count}\nTypedefs: {typedef_count}\nFunction types: {functype_count}\nOther: {other_count}\n")
            f.write(f"Total: {struct_count + union_count + enum_count + typedef_count + functype_count + other_count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Types dump complete: {struct_count}s {union_count}u {enum_count}e {typedef_count}t {functype_count}f -> {filepath}")

# ============================================================================
# 10. DUMP ALL STRINGS
# ============================================================================

def dump_all_strings():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_STRINGS.txt")
    log_info(f"=== [10/25] STRINGS === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Collecting strings...")
    count = 0
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL STRINGS DUMP\n")
            f.write("=" * 80 + "\n\n")
            for s in idautils.Strings():
                if count % 5000 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Collecting strings... {count}")
                count += 1
                try:
                    content = idc.get_strlit_contents(s.ea, s.length, s.strtype)
                    if content:
                        if isinstance(content, bytes):
                            try: content = content.decode('utf-8', errors='replace')
                            except Exception: content = content.decode('latin-1', errors='replace')
                        seg_name = idc.get_segm_name(s.ea) or "unknown"
                        f.write(f"{seg_name}:{s.ea:016X}\t{s.length:04d}\t{content}\n")
                except Exception: pass
            f.write(f"\nTotal strings: {count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Strings dump complete: {count} -> {filepath}")

# ============================================================================
# 11. DUMP ALL NAMES
# ============================================================================

def dump_all_names():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_NAMES.txt")
    log_info(f"=== [11/25] NAMES === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Collecting names...")
    count = 0
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL NAMES DUMP\n")
            f.write("=" * 80 + "\n\n")
            for ea, name in idautils.Names():
                if count % 5000 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Collecting names... {count}")
                count += 1
                seg_name = idc.get_segm_name(ea) or "unknown"
                flags = idc.get_full_flags(ea)
                if idc.is_code(flags): item_type = "CODE"
                elif idc.is_data(flags): item_type = "DATA"
                else: item_type = "UNKN"
                f.write(f"{seg_name}:{ea:016X}\t{item_type}\t{name}\n")
            f.write(f"\nTotal names: {count}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Names dump complete: {count} -> {filepath}")

# ============================================================================
# 12. DUMP ALL IMPORTS
# ============================================================================

def dump_all_imports():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_IMPORTS.txt")
    log_info(f"=== [12/25] IMPORTS === Dumping to: {filepath}")
    count = 0
    nimps = ida_nalt.get_import_module_qty()
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL IMPORTS DUMP\n")
        f.write("=" * 80 + "\n\n")
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i) or f"module_{i}"
            f.write(f"\n[MODULE] {module_name}\n" + "-" * 60 + "\n")
            def imp_cb(ea, name, ordinal):
                nonlocal count
                count += 1
                if name: f.write(f"  {ea:016X}\t{name}\n")
                else: f.write(f"  {ea:016X}\tordinal_{ordinal}\n")
                return True
            ida_nalt.enum_import_names(i, imp_cb)
        f.write(f"\nTotal imports: {count}\n")
    log_info(f"Imports dump complete: {count} from {nimps} modules -> {filepath}")

# ============================================================================
# 13. DUMP ALL EXPORTS
# ============================================================================

def dump_all_exports():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_EXPORTS.txt")
    log_info(f"=== [13/25] EXPORTS === Dumping to: {filepath}")
    count = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL EXPORTS DUMP\n")
        f.write("=" * 80 + "\n\n")
        for entry in idautils.Entries():
            count += 1
            idx, ordinal, ea, name = entry
            f.write(f"{ea:016X}\tord:{ordinal}\t{name}\n")
        f.write(f"\nTotal exports: {count}\n")
    log_info(f"Exports dump complete: {count} -> {filepath}")

# ============================================================================
# 14. DUMP ALL SEGMENTS
# ============================================================================

def dump_all_segments():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_SEGMENTS.txt")
    log_info(f"=== [14/25] SEGMENTS === Dumping to: {filepath}")
    count = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL SEGMENTS DUMP\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'Name':<20} {'Start':>18} {'End':>18} {'Size':>12} {'Class':<10} {'Perms'}\n")
        f.write("-" * 100 + "\n")
        for seg_ea in idautils.Segments():
            count += 1
            seg = idaapi.getseg(seg_ea)
            if seg:
                name = idc.get_segm_name(seg_ea) or "unknown"
                perms = ""
                if seg.perm & idaapi.SEGPERM_READ: perms += "R"
                if seg.perm & idaapi.SEGPERM_WRITE: perms += "W"
                if seg.perm & idaapi.SEGPERM_EXEC: perms += "X"
                f.write(f"{name:<20} {seg.start_ea:018X} {seg.end_ea:018X} {seg.end_ea - seg.start_ea:>12} {idaapi.get_segm_class(seg) or '':<10} {perms}\n")
        f.write(f"\nTotal segments: {count}\n")
    log_info(f"Segments dump complete: {count} -> {filepath}")

# ============================================================================
# 15. DUMP ALL VTABLES
# ============================================================================

def dump_all_vtables():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_VTABLES.txt")
    log_info(f"=== [15/25] VTABLES === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Scanning for vtables...")
    vtables = []
    count = 0
    try:
        for ea, name in idautils.Names():
            if count % 10000 == 0:
                if ida_kernwin.user_cancelled(): break
                ida_kernwin.replace_wait_box(f"Scanning... {count} names, {len(vtables)} vtables")
            count += 1
            if name.startswith("??_R0") or ".?AV" in name or ".?AU" in name:
                class_name = name
                if ".?AV" in name:
                    match = re.search(r'\.?\?AV([^@]+)@@', name)
                    if match: class_name = match.group(1)
                elif ".?AU" in name:
                    match = re.search(r'\.?\?AU([^@]+)@@', name)
                    if match: class_name = match.group(1)
                vtables.append((ea, name, class_name))
        for ea, name in idautils.Names():
            if "vftable" in name.lower() or "vtbl" in name.lower() or name.startswith("??_7"):
                class_name = name
                match = re.search(r'\?\?_7([^@]+)@@', name)
                if match: class_name = match.group(1)
                vtables.append((ea, name, class_name))
    finally:
        ida_kernwin.hide_wait_box()
    vtables.sort(key=lambda x: x[2])
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL VTABLES DUMP (RTTI-based)\n")
        f.write("=" * 80 + "\n\n")
        current_class = None
        for ea, full_name, class_name in vtables:
            if class_name != current_class:
                f.write(f"\n[CLASS] {class_name}\n" + "-" * 60 + "\n")
                current_class = class_name
            f.write(f"  {ea:016X}\t{full_name}\n")
            if "vftable" in full_name.lower() or "vtbl" in full_name.lower() or full_name.startswith("??_7"):
                entry_ea = ea
                entry_count = 0
                while True:
                    ptr = _read_ptr(entry_ea)
                    if ptr == 0 or ptr == idaapi.BADADDR: break
                    if idc.is_code(idc.get_full_flags(ptr)):
                        fn = idc.get_func_name(ptr) or f"sub_{ptr:X}"
                        f.write(f"    [{entry_count}] {ptr:016X} -> {fn}\n")
                        entry_count += 1
                        entry_ea += _ptr_size()
                    else:
                        break
        f.write(f"\nTotal RTTI/vtable entries: {len(vtables)}\n")
    log_info(f"VTables dump complete: {len(vtables)} -> {filepath}")

# ============================================================================
# 16. DUMP ALL RTTI
# ============================================================================

def dump_all_rtti():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_RTTI.txt")
    log_info(f"=== [16/25] RTTI === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Scanning for RTTI...")
    classes = {}
    count = 0
    try:
        for ea, name in idautils.Names():
            if count % 10000 == 0:
                if ida_kernwin.user_cancelled(): break
                ida_kernwin.replace_wait_box(f"Scanning RTTI... {count}")
            count += 1
            if ".?AV" in name or ".?AU" in name:
                match = re.search(r'\.?\?A[VU](.+?)@@', name)
                if match:
                    cn = match.group(1).replace("@", "::")
                    classes.setdefault(cn, {'type_desc': [], 'vtables': [], 'base_classes': []})
                    classes[cn]['type_desc'].append(ea)
            elif "??_R1" in name:
                match = re.search(r'\?\?_R1.+?@(.+?)@@', name)
                if match:
                    cn = match.group(1).replace("@", "::")
                    classes.setdefault(cn, {'type_desc': [], 'vtables': [], 'base_classes': []})
                    classes[cn]['base_classes'].append((ea, name))
            elif name.startswith("??_7"):
                match = re.search(r'\?\?_7(.+?)@@', name)
                if match:
                    cn = match.group(1).replace("@", "::")
                    classes.setdefault(cn, {'type_desc': [], 'vtables': [], 'base_classes': []})
                    classes[cn]['vtables'].append(ea)
    finally:
        ida_kernwin.hide_wait_box()
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL RTTI DUMP (C++ Class Information)\n")
        f.write("=" * 80 + "\n\n")
        for cn in sorted(classes.keys()):
            info = classes[cn]
            f.write(f"\n[CLASS] {cn}\n" + "-" * 60 + "\n")
            if info['type_desc']:
                f.write("  Type Descriptors:\n")
                for ea in info['type_desc']: f.write(f"    {ea:016X}\n")
            if info['vtables']:
                f.write("  VTables:\n")
                for ea in info['vtables']: f.write(f"    {ea:016X}\n")
            if info['base_classes']:
                f.write("  Base Class Info:\n")
                for ea, bname in info['base_classes']: f.write(f"    {ea:016X} {bname}\n")
        f.write(f"\nTotal classes found: {len(classes)}\n")
    log_info(f"RTTI dump complete: {len(classes)} classes -> {filepath}")

# ============================================================================
# 17. DUMP ALL XREFS
# ============================================================================

def dump_all_xrefs():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_XREFS.txt")
    log_info(f"=== [17/25] XREFS === Dumping to: {filepath}")
    ida_kernwin.show_wait_box("Collecting xrefs...")
    func_list = list(idautils.Functions())
    total = len(func_list)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL CROSS-REFERENCES DUMP\n")
            f.write("=" * 80 + "\n\n")
            for i, func_ea in enumerate(func_list):
                if i % 500 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Collecting xrefs... {i}/{total}")
                if i % 2000 == 0 and i > 0:
                    log_progress("Xrefs", i, total)
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                callers = []
                for xref in idautils.XrefsTo(func_ea):
                    cf = ida_funcs.get_func(xref.frm)
                    if cf:
                        callers.append((xref.frm, idc.get_func_name(cf.start_ea) or f"sub_{cf.start_ea:X}"))
                callees = []
                func = ida_funcs.get_func(func_ea)
                if func:
                    for head in idautils.Heads(func.start_ea, func.end_ea):
                        for xref in idautils.XrefsFrom(head):
                            if xref.type in [idaapi.fl_CF, idaapi.fl_CN]:
                                callees.append((xref.to, idc.get_func_name(xref.to) or f"sub_{xref.to:X}"))
                if callers or callees:
                    f.write(f"\n[FUNC] {func_name} (0x{func_ea:X})\n")
                    if callers:
                        f.write(f"  Called by ({len(callers)}):\n")
                        for addr, name in callers: f.write(f"    {addr:016X} {name}\n")
                    if callees:
                        unique = list(set(callees))
                        f.write(f"  Calls ({len(unique)}):\n")
                        for addr, name in sorted(unique): f.write(f"    {addr:016X} {name}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Xrefs dump complete -> {filepath}")

# ============================================================================
# 18. DUMP ALL STRUCTURES
# ============================================================================

def dump_all_structures():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_STRUCTURES.txt")
    log_info(f"=== [18/25] STRUCTURES === Dumping to: {filepath}")
    til = ida_typeinf.get_idati()
    if not til: log_info("ERROR: Could not get type library"); return
    try:
        ordinal_limit = ida_typeinf.get_ordinal_count(til)
    except Exception:
        try: ordinal_limit = ida_typeinf.get_ordinal_qty(til)
        except Exception: ordinal_limit = 0
    count = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL STRUCTURES DUMP\n")
        f.write("=" * 80 + "\n\n")
        for ordinal in range(1, ordinal_limit + 1):
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_numbered_type(til, ordinal): continue
            name = tinfo.get_type_name() or f"type_{ordinal}"
            if tinfo.is_struct() or tinfo.is_union():
                count += 1
                kind = "UNION" if tinfo.is_union() else "STRUCT"
                size = tinfo.get_size()
                f.write(f"\n[{kind}] {name} (size: {size} bytes)\n" + "-" * 60 + "\n")
                udt = ida_typeinf.udt_type_data_t()
                if tinfo.get_udt_details(udt):
                    for mi in range(udt.size()):
                        member = udt[mi]
                        mname = member.name if member.name else f"field_{mi}"
                        moff = member.offset // 8
                        msize = member.size // 8
                        mtype_str = member.type.dstr() if member.type else ""
                        if mtype_str: f.write(f"  +0x{moff:04X} {mname} : {mtype_str} ({msize} bytes)\n")
                        else: f.write(f"  +0x{moff:04X} {mname} ({msize} bytes)\n")
        f.write(f"\nTotal structures: {count}\n")
    log_info(f"Structures dump complete: {count} -> {filepath}")

# ============================================================================
# 19. DUMP ALL PROBLEMS
# ============================================================================

def dump_all_problems():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_PROBLEMS.txt")
    log_info(f"=== [19/25] PROBLEMS === Dumping to: {filepath}")
    problem_types = []
    for attr_name in ['PR_NOBASE', 'PR_NONAME', 'PR_NOFOP', 'PR_NOCMT', 'PR_NOXREFS',
                       'PR_JUMP', 'PR_DISASM', 'PR_HEAD', 'PR_ILLADDR', 'PR_MANYLINES',
                       'PR_BADSTACK', 'PR_ATTN', 'PR_FINAL', 'PR_ROLLED', 'PR_COLLISION', 'PR_DECIMP']:
        val = getattr(ida_problems, attr_name, None)
        if val is not None:
            problem_types.append((attr_name, val))
    total_problems = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL ANALYSIS PROBLEMS\n")
        f.write("=" * 80 + "\n\n")
        for pname, ptype in problem_types:
            problems_for_type = []
            ea = ida_ida.inf_get_min_ea()
            while True:
                ea = ida_problems.get_problem(ptype, ea)
                if ea == idaapi.BADADDR: break
                try: desc = ida_problems.get_problem_name(ptype)
                except Exception: desc = pname
                fn = idc.get_func_name(ea) or ""
                problems_for_type.append((ea, desc, fn))
                ea += 1
            if problems_for_type:
                f.write(f"\n[{pname}] ({len(problems_for_type)} issues)\n" + "-" * 60 + "\n")
                for ea, desc, fn in problems_for_type:
                    loc = f"0x{ea:X}"
                    if fn: loc += f" ({fn})"
                    f.write(f"  {loc}: {desc}\n")
                total_problems += len(problems_for_type)
        f.write(f"\nTotal problems: {total_problems}\n")
    log_info(f"Problems dump complete: {total_problems} -> {filepath}")

# ============================================================================
# 20. DUMP ALL TRY/CATCH BLOCKS
# ============================================================================

def dump_all_tryblks():
    if ida_tryblks is None:
        log_info("ida_tryblks not available, skipping"); return
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_TRYBLKS.txt")
    log_info(f"=== [20/25] TRY/CATCH === Dumping to: {filepath}")
    func_list = list(idautils.Functions())
    total = len(func_list)
    total_blocks = 0
    ida_kernwin.show_wait_box(f"Scanning try/catch... 0/{total}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL TRY/CATCH/SEH BLOCKS\n")
            f.write("=" * 80 + "\n\n")
            for i, func_ea in enumerate(func_list):
                if i % 500 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Try/catch... {i}/{total}")
                pfn = ida_funcs.get_func(func_ea)
                if not pfn: continue
                try:
                    tbv = ida_tryblks.tryblks_t()
                    rng = idaapi.range_t(pfn.start_ea, pfn.end_ea)
                    n = ida_tryblks.get_tryblks(tbv, rng)
                    if n > 0:
                        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                        f.write(f"\n[FUNC] {func_name} (0x{func_ea:X}) - {n} try block(s)\n" + "-" * 60 + "\n")
                        for ti in range(n):
                            tb = tbv[ti]
                            total_blocks += 1
                            f.write(f"  Try block #{ti}: 0x{tb.start_ea:X} - 0x{tb.end_ea:X}\n")
                            try:
                                if tb.is_seh(): f.write("    Type: SEH\n")
                                elif tb.is_cpp():
                                    f.write("    Type: C++\n")
                                    try:
                                        catches = tb.cpp()
                                        for ci in range(catches.size()):
                                            ct = catches[ci]
                                            f.write(f"    Catch #{ci}: 0x{ct.start_ea:X}-0x{ct.end_ea:X}\n")
                                    except Exception: pass
                                else: f.write("    Type: unknown\n")
                            except Exception: f.write("    Type: (could not determine)\n")
                except Exception: pass
            f.write(f"\nTotal try blocks: {total_blocks}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Try/catch dump complete: {total_blocks} -> {filepath}")

# ============================================================================
# 21. DUMP ALL FIXUPS
# ============================================================================

def dump_all_fixups():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_FIXUPS.txt")
    log_info(f"=== [21/25] FIXUPS === Dumping to: {filepath}")
    count = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL FIXUPS / RELOCATIONS\n")
        f.write("=" * 80 + "\n\n")
        ea = ida_fixup.get_first_fixup_ea()
        while ea != idaapi.BADADDR:
            count += 1
            fd = ida_fixup.fixup_data_t()
            ok = ida_fixup.get_fixup(fd, ea)
            if ok:
                desc = ""
                try: desc = ida_fixup.get_fixup_desc(ea, fd)
                except Exception: pass
                seg_name = idc.get_segm_name(ea) or "?"
                fn = idc.get_func_name(ea) or ""
                loc = f"{seg_name}:{ea:016X}"
                if fn: loc += f" ({fn})"
                f.write(f"{loc}")
                try: f.write(f"  type=0x{fd.get_type():X}")
                except Exception: pass
                if desc: f.write(f"  {desc}")
                f.write("\n")
            else:
                f.write(f"0x{ea:X}  (could not read fixup data)\n")
            ea = ida_fixup.get_next_fixup_ea(ea)
        f.write(f"\nTotal fixups: {count}\n")
    log_info(f"Fixups dump complete: {count} -> {filepath}")

# ============================================================================
# 22. DUMP ALL PATCHED BYTES
# ============================================================================

def dump_all_patched_bytes():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_PATCHED_BYTES.txt")
    log_info(f"=== [22/25] PATCHED BYTES === Dumping to: {filepath}")
    patches = []
    class _pv(object):
        def __init__(self): self.skip = 0; self.patch = 0
        def __call__(self, ea, fpos, o, v, cnt=()):
            if fpos == -1: self.skip += 1; patches.append((ea, -1, o, v, "skipped"))
            else: self.patch += 1; patches.append((ea, fpos, o, v, "patched"))
            return 0
    v = _pv()
    ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, v)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL PATCHED BYTES\n")
        f.write("=" * 80 + "\n\n")
        for ea, fpos, orig, patched, status in patches:
            seg_name = idc.get_segm_name(ea) or "?"
            fn = idc.get_func_name(ea) or ""
            loc = f"{seg_name}:{ea:016X}"
            if fn: loc += f" ({fn})"
            f.write(f"{loc}  fpos=0x{fpos:X}  orig=0x{orig:02X}  new=0x{patched:02X}  [{status}]\n")
        f.write(f"\nTotal: {v.patch} patched, {v.skip} skipped\n")
    log_info(f"Patched bytes dump complete: {v.patch} patched, {v.skip} skipped -> {filepath}")

# ============================================================================
# 23. DUMP ALL HIDDEN RANGES
# ============================================================================

def dump_all_hidden_ranges():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_HIDDEN_RANGES.txt")
    log_info(f"=== [23/25] HIDDEN RANGES === Dumping to: {filepath}")
    count = 0
    try: qty = ida_bytes.get_hidden_range_qty()
    except Exception: qty = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL HIDDEN RANGES\n")
        f.write("=" * 80 + "\n\n")
        for i in range(qty):
            try:
                hr = ida_bytes.getn_hidden_range(i)
                if hr:
                    count += 1
                    f.write(f"Range #{i}: 0x{hr.start_ea:X} - 0x{hr.end_ea:X} ({hr.end_ea - hr.start_ea} bytes)\n")
                    try:
                        if hr.description: f.write(f"  Description: {hr.description}\n")
                    except Exception: pass
                    try:
                        if hr.header: f.write(f"  Header: {hr.header}\n")
                    except Exception: pass
                    try:
                        if hr.footer: f.write(f"  Footer: {hr.footer}\n")
                    except Exception: pass
                    try: f.write(f"  Visible: {hr.visible}\n")
                    except Exception: pass
            except Exception: pass
        f.write(f"\nTotal hidden ranges: {count}\n")
    log_info(f"Hidden ranges dump complete: {count} -> {filepath}")

# ============================================================================
# 24. DUMP ALL BOOKMARKS
# ============================================================================

def dump_all_bookmarks():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_BOOKMARKS.txt")
    log_info(f"=== [24/25] BOOKMARKS === Dumping to: {filepath}")
    count = 0
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ALL BOOKMARKS / MARKED POSITIONS\n")
        f.write("=" * 80 + "\n\n")
        # Method 1: ida_moves.bookmarks_t
        if ida_moves is not None:
            try:
                widget = ida_kernwin.find_widget("IDA View-A")
                if widget:
                    ud = ida_kernwin.get_viewer_user_data(widget)
                    for loc, desc in ida_moves.bookmarks_t(widget):
                        count += 1
                        try: place_str = loc.place()._print(ud)
                        except Exception: place_str = str(loc)
                        f.write(f"  [{count}] {place_str}: {desc}\n")
            except Exception: pass
        # Method 2: idc fallback
        if count == 0:
            try:
                for slot in range(1024):
                    ea = idc.get_bookmark(slot)
                    if ea is None or ea == idaapi.BADADDR: continue
                    desc = idc.get_bookmark_desc(slot) or ""
                    count += 1
                    fn = idc.get_func_name(ea) or ""
                    loc = f"0x{ea:X}"
                    if fn: loc += f" ({fn})"
                    f.write(f"  [slot {slot}] {loc}: {desc}\n")
            except Exception: pass
        f.write(f"\nTotal bookmarks: {count}\n")
    log_info(f"Bookmarks dump complete: {count} -> {filepath}")

# ============================================================================
# 25. DUMP ALL SWITCH TABLES
# ============================================================================

def dump_all_switch_tables():
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_SWITCH_TABLES.txt")
    log_info(f"=== [25/25] SWITCH TABLES === Dumping to: {filepath}")
    func_list = list(idautils.Functions())
    total = len(func_list)
    total_switches = 0
    ida_kernwin.show_wait_box(f"Scanning switch tables... 0/{total}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("ALL SWITCH / JUMP TABLES\n")
            f.write("=" * 80 + "\n\n")
            for i, func_ea in enumerate(func_list):
                if i % 500 == 0:
                    if ida_kernwin.user_cancelled(): break
                    ida_kernwin.replace_wait_box(f"Switch tables... {i}/{total}")
                if i % 2000 == 0 and i > 0:
                    log_progress("SwitchTables", i, total)
                pfn = ida_funcs.get_func(func_ea)
                if not pfn: continue
                func_switches = []
                for head in idautils.Heads(pfn.start_ea, pfn.end_ea):
                    si = ida_nalt.get_switch_info(head)
                    if si: func_switches.append((head, si))
                if func_switches:
                    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                    f.write(f"\n[FUNC] {func_name} (0x{func_ea:X}) - {len(func_switches)} switch(es)\n" + "-" * 60 + "\n")
                    for sw_ea, si in func_switches:
                        total_switches += 1
                        f.write(f"  Switch at 0x{sw_ea:X}:\n")
                        try: f.write(f"    Cases: {si.get_jtable_size()}\n")
                        except Exception:
                            try: f.write(f"    Cases: {si.ncases}\n")
                            except Exception: pass
                        try: f.write(f"    Jump table: 0x{si.jumps:X}\n")
                        except Exception: pass
                        try:
                            if si.lowcase != 0: f.write(f"    Low case: {si.lowcase}\n")
                        except Exception: pass
                        try:
                            if si.defjump != idaapi.BADADDR: f.write(f"    Default jump: 0x{si.defjump:X}\n")
                        except Exception: pass
                        try: f.write(f"    Start EA: 0x{si.startea:X}\n")
                        except Exception: pass
                        # Dump individual cases
                        try:
                            jtable_size = si.get_jtable_size()
                        except Exception:
                            try: jtable_size = si.ncases
                            except Exception: jtable_size = 0
                        if jtable_size > 0:
                            try:
                                jumps_ea = si.jumps
                                elem_size = si.get_jtable_element_size()
                                for ci in range(jtable_size):
                                    case_ea = jumps_ea + ci * elem_size
                                    if elem_size == 2: target = idc.get_wide_word(case_ea)
                                    elif elem_size == 4: target = idc.get_wide_dword(case_ea)
                                    elif elem_size == 8: target = idc.get_qword(case_ea)
                                    else: target = _read_ptr(case_ea)
                                    f.write(f"    Case [{ci}] -> 0x{target:X}\n")
                            except Exception: pass
            f.write(f"\nTotal switch tables: {total_switches}\n")
    finally:
        ida_kernwin.hide_wait_box()
    log_info(f"Switch tables dump complete: {total_switches} -> {filepath}")

# ============================================================================
# DUMP EVERYTHING
# ============================================================================

# Expected output files for each dump task — used to skip re-dumping
_TASK_OUTPUT_FILES = {
    "Overview":         "ALL_OVERVIEW.txt",
    "Assembly":         "ALL_ASSEMBLY.asm",
    "Segments":         "ALL_SEGMENTS.txt",
    "Strings":          "ALL_STRINGS.txt",
    "String Xrefs":     "ALL_STRING_XREFS.txt",
    "Names":            "ALL_NAMES.txt",
    "Imports":          "ALL_IMPORTS.txt",
    "Exports":          "ALL_EXPORTS.txt",
    "Data Variables":   "ALL_DATA_VARIABLES.txt",
    "Comments":         "ALL_COMMENTS.txt",
    "Types":            "ALL_TYPES.txt",
    "Structures":       "ALL_STRUCTURES.txt",
    "RTTI":             "ALL_RTTI.txt",
    "VTables":          "ALL_VTABLES.txt",
    "Xrefs":            "ALL_XREFS.txt",
    "Call Graph":       "ALL_CALL_GRAPH.txt",
    "Function Details": "ALL_FUNCTION_DETAILS.txt",
    "Problems":         "ALL_PROBLEMS.txt",
    "Try/Catch":        "ALL_TRYBLKS.txt",
    "Fixups":           "ALL_FIXUPS.txt",
    "Patched Bytes":    "ALL_PATCHED_BYTES.txt",
    "Hidden Ranges":    "ALL_HIDDEN_RANGES.txt",
    "Bookmarks":        "ALL_BOOKMARKS.txt",
    "Switch Tables":    "ALL_SWITCH_TABLES.txt",
    "Decompiled":       "ALL_DECOMPILED.c",
}


def _dump_file_is_valid(outdir, filename):
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
        total_funcs = len(list(idautils.Functions()))
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                f.seek(max(0, size - 500))
                tail = f.read()
                m = re.search(r'Total functions:\s*(\d+)', tail)
                if m:
                    dumped = int(m.group(1))
                    if dumped == total_funcs:
                        return True
                    return False  # count mismatch
                m = re.search(r'(\d+)\s+decompiled.*?(\d+)\s+failed.*?of\s+(\d+)', tail)
                if m:
                    done = int(m.group(1)) + int(m.group(2))
                    expected = int(m.group(3))
                    if expected == total_funcs:
                        return True
                    return False
                m = re.search(r'(\d+)/(\d+)\s+functions', tail)
                if m and int(m.group(2)) == total_funcs:
                    return True
                return True  # file exists, can't verify, accept it
        except Exception:
            return True
    return True  # non-function file, exists and non-trivial


def dump_everything():
    log_info("=" * 60)
    log_info("=== DUMPING EVERYTHING ===")
    log_info("=" * 60)
    start_time = time.time()
    outdir = ensure_output_dir()
    dump_funcs = [
        ("Overview",         dump_binary_overview),
        ("Assembly",         dump_all_assembly),
        ("Segments",         dump_all_segments),
        ("Strings",          dump_all_strings),
        ("String Xrefs",     dump_all_string_xrefs),
        ("Names",            dump_all_names),
        ("Imports",          dump_all_imports),
        ("Exports",          dump_all_exports),
        ("Data Variables",   dump_all_data_variables),
        ("Comments",         dump_all_comments),
        ("Types",            dump_all_types),
        ("Structures",       dump_all_structures),
        ("RTTI",             dump_all_rtti),
        ("VTables",          dump_all_vtables),
        ("Xrefs",            dump_all_xrefs),
        ("Call Graph",       dump_all_call_graph),
        ("Function Details", dump_all_function_details),
        ("Problems",         dump_all_problems),
        ("Try/Catch",        dump_all_tryblks),
        ("Fixups",           dump_all_fixups),
        ("Patched Bytes",    dump_all_patched_bytes),
        ("Hidden Ranges",    dump_all_hidden_ranges),
        ("Bookmarks",        dump_all_bookmarks),
        ("Switch Tables",    dump_all_switch_tables),
    ]
    failed = []
    skipped = []
    for i, (name, func) in enumerate(dump_funcs):
        expected_file = _TASK_OUTPUT_FILES.get(name)
        if expected_file and _dump_file_is_valid(outdir, expected_file):
            log_info(f"--- SKIP {name} ({i+1}/{len(dump_funcs)}) — {expected_file} already exists and is complete ---")
            skipped.append(name)
            continue
        log_info(f"--- Starting {name} ({i+1}/{len(dump_funcs)}) ---")
        try:
            func()
        except Exception as e:
            log_info(f"ERROR dumping {name}: {e}")
            traceback.print_exc()
            failed.append(name)
    # Decompiled requires Hex-Rays
    if _hexrays_ready():
        dec_file = _TASK_OUTPUT_FILES.get("Decompiled")
        if dec_file and _dump_file_is_valid(outdir, dec_file):
            log_info(f"--- SKIP Decompiled — {dec_file} already exists and is complete ---")
            skipped.append("Decompiled")
        else:
            log_info(f"--- Starting Decompiled ({len(dump_funcs)+1}/{len(dump_funcs)+1}) ---")
            try:
                dump_all_decompiled()
            except Exception as e:
                log_info(f"ERROR dumping Decompiled: {e}")
                failed.append("Decompiled")
    else:
        log_info("Hex-Rays not available, skipping decompilation")
    elapsed = time.time() - start_time
    log_info("=" * 60)
    total_tasks = len(dump_funcs) + 1
    dumped = total_tasks - len(failed) - len(skipped)
    summary = f"Dumped: {dumped}, Skipped (existing): {len(skipped)}, Failed: {len(failed)}"
    if failed:
        log_info(f"=== COMPLETE in {elapsed:.1f}s — {summary} (errors: {', '.join(failed)}) ===")
    else:
        log_info(f"=== COMPLETE in {elapsed:.1f}s — {summary} ===")
    if skipped:
        log_info(f"Skipped (already dumped): {', '.join(skipped)}")
    log_info("=" * 60)

# ============================================================================
# RIGHT-CLICK HELPERS
# ============================================================================

def get_selected_func_ea():
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func: return func.start_ea
    if idc.get_func_name(ea): return ea
    return None

def get_selected_string():
    ea = idc.get_screen_ea()
    str_type = idc.get_str_type(ea)
    if str_type is not None and str_type >= 0:
        content = idc.get_strlit_contents(ea, -1, str_type)
        if content:
            if isinstance(content, bytes):
                try: content = content.decode('utf-8', errors='replace')
                except Exception: content = content.decode('latin-1', errors='replace')
            return (ea, content)
    return None

def dump_string_xrefs_single(str_ea, str_content):
    safe_content = sanitize_filename(str_content[:50]) if str_content else f"str_{str_ea:X}"
    outdir = ensure_output_dir("string_xrefs")
    filepath = os.path.join(outdir, f"{safe_content}_xrefs.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"XREFS TO STRING\nAddress: 0x{str_ea:X}\nContent: \"{str_content}\"\n")
        f.write("=" * 80 + "\n\n")
        refs = []
        for xref in idautils.XrefsTo(str_ea):
            rf = ida_funcs.get_func(xref.frm)
            if rf:
                refs.append((xref.frm, idc.get_func_name(rf.start_ea) or f"sub_{rf.start_ea:X}", rf.start_ea))
            else:
                refs.append((xref.frm, idc.get_name(xref.frm) or f"data_{xref.frm:X}", None))
        func_refs = {}
        data_refs = []
        for addr, name, fs in refs:
            if fs:
                func_refs.setdefault(fs, {'name': name, 'addrs': []})
                func_refs[fs]['addrs'].append(addr)
            else:
                data_refs.append((addr, name))
        if func_refs:
            f.write("Functions:\n")
            for fs, info in sorted(func_refs.items()):
                f.write(f"  {fs:016X}  {info['name']}\n")
                for addr in info['addrs']: f.write(f"    -> ref at {addr:016X}\n")
        if data_refs:
            f.write("\nData references:\n")
            for addr, name in data_refs: f.write(f"  {addr:016X}  {name}\n")
        f.write(f"\nTotal references: {len(refs)} ({len(func_refs)} functions, {len(data_refs)} data)\n")
    log_info(f"String xrefs saved to: {filepath}")

def dump_function_xrefs(func_ea):
    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
    safe_name = sanitize_filename(func_name)
    outdir = ensure_output_dir("function_xrefs")
    filepath = os.path.join(outdir, f"{safe_name}_xrefs.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"XREFS FOR: {func_name}\nAddress: 0x{func_ea:X}\n")
        f.write("=" * 80 + "\n\n")
        fs = get_function_strings(func_ea)
        if fs:
            f.write("[STRINGS]\n" + "-" * 40 + "\n")
            for addr, s in fs: f.write(f"  {addr:016X}  \"{s.replace(chr(10), '\\\\n').replace(chr(13), '\\\\r')}\"\n")
            f.write(f"Total: {len(fs)}\n\n")
        f.write("[CALLED BY]\n" + "-" * 40 + "\n")
        seen = set()
        for xref in idautils.XrefsTo(func_ea):
            cf = ida_funcs.get_func(xref.frm)
            if cf and cf.start_ea not in seen:
                seen.add(cf.start_ea)
                f.write(f"  {xref.frm:016X}  {idc.get_func_name(cf.start_ea) or f'sub_{cf.start_ea:X}'}\n")
        f.write(f"Total callers: {len(seen)}\n\n")
        f.write("[CALLS]\n" + "-" * 40 + "\n")
        seen = set()
        func = ida_funcs.get_func(func_ea)
        if func:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref.type in [idaapi.fl_CF, idaapi.fl_CN] and xref.to not in seen:
                        seen.add(xref.to)
                        f.write(f"  {xref.to:016X}  {idc.get_func_name(xref.to) or f'sub_{xref.to:X}'}\n")
        f.write(f"Total calls: {len(seen)}\n\n")
        f.write("[DATA REFS FROM]\n" + "-" * 40 + "\n")
        seen = set()
        if func:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref.type in [idaapi.dr_O, idaapi.dr_R, idaapi.dr_W] and xref.to not in seen:
                        seen.add(xref.to)
                        f.write(f"  {xref.to:016X}  {idc.get_name(xref.to) or f'data_{xref.to:X}'}\n")
        f.write(f"Total data refs: {len(seen)}\n")
    log_info(f"Xrefs for {func_name} saved to: {filepath}")

def dump_function_all(func_ea):
    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
    safe_name = sanitize_filename(func_name)
    outdir = ensure_output_dir("function_dumps")
    filepath = os.path.join(outdir, f"{safe_name}_full.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"FULL DUMP: {func_name}\nAddress: 0x{func_ea:X}\n")
        f.write("=" * 80 + "\n\n")
        f.write("=" * 40 + " ASSEMBLY " + "=" * 40 + "\n")
        asm = get_function_assembly(func_ea)
        f.write(asm if asm else "; Failed to get assembly")
        f.write("\n\n" + "=" * 40 + " DECOMPILED " + "=" * 40 + "\n")
        dec = get_function_decompiled(func_ea)
        f.write(dec if dec else "// Decompilation not available")
        f.write("\n\n" + "=" * 40 + " STRINGS " + "=" * 40 + "\n")
        fs = get_function_strings(func_ea)
        if fs:
            for addr, s in fs: f.write(f"  {addr:016X}  \"{s.replace(chr(10), '\\\\n')}\"\n")
        else:
            f.write("  (no strings found)\n")
        f.write("\n" + "=" * 40 + " XREFS " + "=" * 40 + "\n\n[CALLED BY]\n")
        seen = set()
        for xref in idautils.XrefsTo(func_ea):
            cf = ida_funcs.get_func(xref.frm)
            if cf and cf.start_ea not in seen:
                seen.add(cf.start_ea)
                f.write(f"  {xref.frm:016X}  {idc.get_func_name(cf.start_ea)}\n")
        f.write("\n[CALLS]\n")
        seen = set()
        func = ida_funcs.get_func(func_ea)
        if func:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref.type in [idaapi.fl_CF, idaapi.fl_CN] and xref.to not in seen:
                        seen.add(xref.to)
                        f.write(f"  {xref.to:016X}  {idc.get_func_name(xref.to) or f'sub_{xref.to:X}'}\n")
    log_info(f"Full dump for {func_name} saved to: {filepath}")

# ============================================================================
# ACTION HANDLERS
# ============================================================================

class CopyAssemblyAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        func = ida_funcs.get_func(idc.get_screen_ea())
        if not func: return 1
        asm = get_function_assembly(func.start_ea)
        if asm: copy_to_clipboard(asm); log_info(f"Copied assembly for {idc.get_func_name(func.start_ea)}")
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE

class CopyDecompiledAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        func = ida_funcs.get_func(idc.get_screen_ea())
        if not func: return 1
        fn = idc.get_func_name(func.start_ea) or f"func_{func.start_ea:X}"
        dec = get_function_decompiled(func.start_ea)
        if dec: copy_to_clipboard(f"// Function: {fn}\n// Address: 0x{func.start_ea:X}\n\n" + dec)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE] else idaapi.AST_DISABLE

class CopyAllAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        func = ida_funcs.get_func(idc.get_screen_ea())
        if not func: return 1
        fn = idc.get_func_name(func.start_ea)
        parts = [f"{'='*80}\nFUNCTION: {fn} (0x{func.start_ea:X})\n{'='*80}\n",
                 f"{'-'*40} ASSEMBLY {'-'*40}\n{get_function_assembly(func.start_ea) or '; Failed'}",
                 f"{'-'*40} DECOMPILED {'-'*40}\n{get_function_decompiled(func.start_ea) or '// Failed'}"]
        copy_to_clipboard("\n\n".join(parts))
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE] else idaapi.AST_DISABLE

def _make_dump_action(dump_func):
    class _A(idaapi.action_handler_t):
        def __init__(self): idaapi.action_handler_t.__init__(self)
        def activate(self, ctx): dump_func(); return 1
        def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS
    return _A

DumpAllAssemblyAction     = _make_dump_action(dump_all_assembly)
DumpAllDecompiledAction   = _make_dump_action(dump_all_decompiled)
DumpAllStringsAction      = _make_dump_action(dump_all_strings)
DumpEverythingAction      = _make_dump_action(dump_everything)
DumpNamesAction           = _make_dump_action(dump_all_names)
DumpImportsAction         = _make_dump_action(dump_all_imports)
DumpExportsAction         = _make_dump_action(dump_all_exports)
DumpSegmentsAction        = _make_dump_action(dump_all_segments)
DumpVTablesAction         = _make_dump_action(dump_all_vtables)
DumpRTTIAction            = _make_dump_action(dump_all_rtti)
DumpXrefsAction           = _make_dump_action(dump_all_xrefs)
DumpStructuresAction      = _make_dump_action(dump_all_structures)
DumpOverviewAction        = _make_dump_action(dump_binary_overview)
DumpFuncDetailsAction     = _make_dump_action(dump_all_function_details)
DumpCallGraphAction       = _make_dump_action(dump_all_call_graph)
DumpStringXrefsAction     = _make_dump_action(dump_all_string_xrefs)
DumpDataVarsAction        = _make_dump_action(dump_all_data_variables)
DumpCommentsAction        = _make_dump_action(dump_all_comments)
DumpTypesAction           = _make_dump_action(dump_all_types)
DumpProblemsAction        = _make_dump_action(dump_all_problems)
DumpTryBlksAction         = _make_dump_action(dump_all_tryblks)
DumpFixupsAction          = _make_dump_action(dump_all_fixups)
DumpPatchedBytesAction    = _make_dump_action(dump_all_patched_bytes)
DumpHiddenRangesAction    = _make_dump_action(dump_all_hidden_ranges)
DumpBookmarksAction       = _make_dump_action(dump_all_bookmarks)
DumpSwitchTablesAction    = _make_dump_action(dump_all_switch_tables)

class DumpFunctionAssemblyAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        fea = get_selected_func_ea()
        if not fea: return 1
        fn = idc.get_func_name(fea) or f"sub_{fea:X}"
        outdir = ensure_output_dir("function_dumps")
        asm = get_function_assembly(fea)
        if asm:
            with open(os.path.join(outdir, f"{sanitize_filename(fn)}.asm"), "w", encoding="utf-8") as f: f.write(asm)
            log_info(f"Assembly for {fn} saved")
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS] else idaapi.AST_DISABLE

class DumpFunctionDecompiledAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        fea = get_selected_func_ea()
        if not fea: return 1
        fn = idc.get_func_name(fea) or f"sub_{fea:X}"
        outdir = ensure_output_dir("function_dumps")
        dec = get_function_decompiled(fea)
        if dec:
            with open(os.path.join(outdir, f"{sanitize_filename(fn)}.c"), "w", encoding="utf-8") as f: f.write(f"// Function: {fn}\n// Address: 0x{fea:X}\n\n" + dec)
            log_info(f"Decompiled for {fn} saved")
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS] else idaapi.AST_DISABLE

class DumpFunctionXrefsAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        fea = get_selected_func_ea()
        if fea: dump_function_xrefs(fea)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS] else idaapi.AST_DISABLE

class DumpFunctionAllAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        fea = get_selected_func_ea()
        if fea: dump_function_all(fea)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS] else idaapi.AST_DISABLE

class CopyStringAction(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        si = get_selected_string()
        if si: copy_to_clipboard(f"String at 0x{si[0]:X}:\n\"{si[1]}\"")
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_STRINGS, idaapi.BWN_DISASM] else idaapi.AST_DISABLE

class DumpStringXrefsActionSingle(idaapi.action_handler_t):
    def __init__(self): idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        si = get_selected_string()
        if si: dump_string_xrefs_single(*si)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_STRINGS, idaapi.BWN_DISASM] else idaapi.AST_DISABLE

# ============================================================================
# POPUP HOOKS
# ============================================================================

ALL_ACTION_IDS = [
    "dump:copy_asm", "dump:copy_decompiled", "dump:copy_all",
    "dump:copy_string", "dump:string_xrefs",
    "dump:func_asm", "dump:func_decompiled", "dump:func_xrefs", "dump:func_all",
    "dump:all_overview", "dump:all_asm", "dump:all_decompiled", "dump:all_strings",
    "dump:all_string_xrefs", "dump:all_names", "dump:all_imports", "dump:all_exports",
    "dump:all_segments", "dump:all_data_vars", "dump:all_comments", "dump:all_types",
    "dump:all_structures", "dump:all_func_details", "dump:all_call_graph",
    "dump:all_vtables", "dump:all_rtti", "dump:all_xrefs", "dump:all_problems",
    "dump:all_tryblks", "dump:all_fixups", "dump:all_patched_bytes",
    "dump:all_hidden_ranges", "dump:all_bookmarks", "dump:all_switch_tables",
    "dump:everything",
]

class PopupHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wt = idaapi.get_widget_type(widget)
        if wt == idaapi.BWN_STRINGS:
            si = get_selected_string()
            if si:
                sd = si[1][:40].replace('\n', '\\n')
                if len(si[1]) > 40: sd += "..."
                idaapi.update_action_label("dump:copy_string", f"Copy \"{sd}\"")
                idaapi.update_action_label("dump:string_xrefs", f"Dump \"{sd}\" Xrefs")
            idaapi.attach_action_to_popup(widget, popup, "dump:copy_string", None)
            idaapi.attach_action_to_popup(widget, popup, "dump:string_xrefs", None)
            idaapi.attach_action_to_popup(widget, popup, "dump:all_strings", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        if wt == idaapi.BWN_NAMES:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_names", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        if wt == idaapi.BWN_IMPORTS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_imports", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        if wt == idaapi.BWN_EXPORTS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_exports", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        if wt == idaapi.BWN_SEGS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_segments", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        BWN_S = getattr(idaapi, 'BWN_STRUCTS', None) or getattr(idaapi, 'BWN_LOCTYPS', None)
        if BWN_S is not None and wt == BWN_S:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_structures", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_types", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        if wt in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS]:
            fea = get_selected_func_ea()
            fn = ""
            if fea:
                fn = idc.get_func_name(fea) or f"sub_{fea:X}"
                if len(fn) > 40: fn = fn[:37] + "..."
            if fn:
                idaapi.update_action_label("dump:copy_asm", f"Copy {fn} Assembly")
                idaapi.update_action_label("dump:copy_decompiled", f"Copy {fn} Decompiled")
                idaapi.update_action_label("dump:copy_all", f"Copy {fn} (Asm+Decompiled)")
                idaapi.update_action_label("dump:func_asm", f"Dump {fn} Assembly")
                idaapi.update_action_label("dump:func_decompiled", f"Dump {fn} Decompiled")
                idaapi.update_action_label("dump:func_xrefs", f"Dump {fn} Xrefs")
                idaapi.update_action_label("dump:func_all", f"Dump {fn} (Full)")
            if wt == idaapi.BWN_DISASM:
                si = get_selected_string()
                if si:
                    sd = si[1][:30].replace('\n', '\\n')
                    if len(si[1]) > 30: sd += "..."
                    idaapi.update_action_label("dump:copy_string", f"Copy \"{sd}\"")
                    idaapi.update_action_label("dump:string_xrefs", f"Dump \"{sd}\" Xrefs")
                    idaapi.attach_action_to_popup(widget, popup, "dump:copy_string", None)
                    idaapi.attach_action_to_popup(widget, popup, "dump:string_xrefs", None)
            if wt in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE]:
                idaapi.attach_action_to_popup(widget, popup, "dump:copy_asm", None)
                idaapi.attach_action_to_popup(widget, popup, "dump:copy_decompiled", None)
                idaapi.attach_action_to_popup(widget, popup, "dump:copy_all", None)
            idaapi.attach_action_to_popup(widget, popup, "dump:func_asm", "Dump Function/")
            idaapi.attach_action_to_popup(widget, popup, "dump:func_decompiled", "Dump Function/")
            idaapi.attach_action_to_popup(widget, popup, "dump:func_xrefs", "Dump Function/")
            idaapi.attach_action_to_popup(widget, popup, "dump:func_all", "Dump Function/")
            for aid in ["dump:all_overview", "dump:all_asm", "dump:all_decompiled",
                        "dump:all_strings", "dump:all_string_xrefs", "dump:all_names",
                        "dump:all_imports", "dump:all_exports", "dump:all_segments",
                        "dump:all_data_vars", "dump:all_comments", "dump:all_types",
                        "dump:all_structures", "dump:all_func_details", "dump:all_call_graph",
                        "dump:all_vtables", "dump:all_rtti", "dump:all_xrefs",
                        "dump:all_problems", "dump:all_tryblks", "dump:all_fixups",
                        "dump:all_patched_bytes", "dump:all_hidden_ranges",
                        "dump:all_bookmarks", "dump:all_switch_tables", "dump:everything"]:
                idaapi.attach_action_to_popup(widget, popup, aid, "Dump ALL/")

# ============================================================================
# PLUGIN CLASS
# ============================================================================

class DumpAllPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Dump EVERYTHING from the IDA database"
    help = "25 dump types: assembly, decompiled, strings, types, xrefs, comments, and more"
    wanted_name = "Dump All"
    wanted_hotkey = "Ctrl-Shift-D"
    popup_hooks = None

    def init(self):
        log_info("Initializing...")
        actions = [
            ("dump:copy_asm",          "Copy Assembly",             CopyAssemblyAction(),          "Ctrl-Shift-A"),
            ("dump:copy_decompiled",   "Copy Decompiled",           CopyDecompiledAction(),        "Ctrl-Shift-C"),
            ("dump:copy_all",          "Copy ALL (Asm+Decompiled)", CopyAllAction(),               "Ctrl-Shift-X"),
            ("dump:copy_string",       "Copy String",               CopyStringAction(),            ""),
            ("dump:string_xrefs",      "Dump String Xrefs",         DumpStringXrefsActionSingle(), ""),
            ("dump:func_asm",          "Dump Function Assembly",    DumpFunctionAssemblyAction(),  ""),
            ("dump:func_decompiled",   "Dump Function Decompiled",  DumpFunctionDecompiledAction(),""),
            ("dump:func_xrefs",        "Dump Function Xrefs",       DumpFunctionXrefsAction(),     ""),
            ("dump:func_all",          "Dump Function (Full)",      DumpFunctionAllAction(),       ""),
            ("dump:all_overview",      "Dump ALL Overview",         DumpOverviewAction(),          ""),
            ("dump:all_asm",           "Dump ALL Assembly",         DumpAllAssemblyAction(),       ""),
            ("dump:all_decompiled",    "Dump ALL Decompiled",       DumpAllDecompiledAction(),     ""),
            ("dump:all_strings",       "Dump ALL Strings",          DumpAllStringsAction(),        ""),
            ("dump:all_string_xrefs",  "Dump ALL String Xrefs",     DumpStringXrefsAction(),       ""),
            ("dump:all_names",         "Dump ALL Names",            DumpNamesAction(),             ""),
            ("dump:all_imports",       "Dump ALL Imports",          DumpImportsAction(),           ""),
            ("dump:all_exports",       "Dump ALL Exports",          DumpExportsAction(),           ""),
            ("dump:all_segments",      "Dump ALL Segments",         DumpSegmentsAction(),          ""),
            ("dump:all_data_vars",     "Dump ALL Data Variables",   DumpDataVarsAction(),          ""),
            ("dump:all_comments",      "Dump ALL Comments",         DumpCommentsAction(),          ""),
            ("dump:all_types",         "Dump ALL Types",            DumpTypesAction(),             ""),
            ("dump:all_structures",    "Dump ALL Structures",       DumpStructuresAction(),        ""),
            ("dump:all_func_details",  "Dump ALL Function Details", DumpFuncDetailsAction(),       ""),
            ("dump:all_call_graph",    "Dump ALL Call Graph",       DumpCallGraphAction(),         ""),
            ("dump:all_vtables",       "Dump ALL VTables",          DumpVTablesAction(),           ""),
            ("dump:all_rtti",          "Dump ALL RTTI",             DumpRTTIAction(),              ""),
            ("dump:all_xrefs",         "Dump ALL Xrefs",            DumpXrefsAction(),             ""),
            ("dump:all_problems",      "Dump ALL Problems",         DumpProblemsAction(),          ""),
            ("dump:all_tryblks",       "Dump ALL Try/Catch",        DumpTryBlksAction(),           ""),
            ("dump:all_fixups",        "Dump ALL Fixups",           DumpFixupsAction(),            ""),
            ("dump:all_patched_bytes", "Dump ALL Patched Bytes",    DumpPatchedBytesAction(),      ""),
            ("dump:all_hidden_ranges", "Dump ALL Hidden Ranges",    DumpHiddenRangesAction(),      ""),
            ("dump:all_bookmarks",     "Dump ALL Bookmarks",        DumpBookmarksAction(),         ""),
            ("dump:all_switch_tables", "Dump ALL Switch Tables",    DumpSwitchTablesAction(),      ""),
            ("dump:everything",        "Dump EVERYTHING",           DumpEverythingAction(),        ""),
        ]
        for aid, aname, handler, hotkey in actions:
            idaapi.register_action(idaapi.action_desc_t(aid, aname, handler, hotkey, aname, -1))
        self.popup_hooks = PopupHooks()
        self.popup_hooks.hook()
        log_info("Ready! 25 dump types. Right-click for options or Ctrl-Shift-D to dump everything.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        dump_everything()

    def term(self):
        if self.popup_hooks: self.popup_hooks.unhook()
        for aid in ALL_ACTION_IDS: idaapi.unregister_action(aid)
        log_info("Terminated.")

def PLUGIN_ENTRY():
    return DumpAllPlugin()
