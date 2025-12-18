
# IDA Pro 9.0 plugin — Dump ALL functions + strings
# Menu options: Dump All Assembly / Dump All Decompiled / Dump All Strings
from __future__ import print_function
import os, re, traceback

import idaapi
import idc
import idautils
import ida_funcs
import ida_kernwin
import ida_bytes
import ida_nalt

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None

import ida_lines

PLUGIN_NAME = "DumpTookit"
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

def _hexrays_ready():
    if ida_hexrays is None:
        return False
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False

def _pseudocode_text(cf) -> str:
    """Convert cfunc_t pseudocode to plain text lines."""
    out = []
    for ln in cf.get_pseudocode():
        try:
            s = str(ln.line)
        except Exception:
            s = str(ln)
        s = ida_lines.tag_remove(s)
        out.append(s)
    return "\n".join(out)

def get_function_assembly(ea):
    """Get the assembly listing for a function with all comments."""
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
        # Get anterior (before) comments
        for i in range(1000):  # IDA uses E_PREV + index
            anterior = idc.get_extra_cmt(current_ea, idc.E_PREV + i)
            if anterior:
                lines.append(f"; {anterior}")
            else:
                break
        
        # Get the disassembly line with all formatting
        # Use GENDSM_FORCE_CODE to include everything
        disasm = idc.generate_disasm_line(current_ea, idc.GENDSM_FORCE_CODE)
        if disasm:
            disasm = ida_lines.tag_remove(disasm)
            addr_str = f".text:{current_ea:016X}"
            
            # Get regular comment
            cmt = idc.get_cmt(current_ea, 0)  # Regular comment
            rep_cmt = idc.get_cmt(current_ea, 1)  # Repeatable comment
            
            line = f"{addr_str}    {disasm}"
            
            # Append comments if they exist and aren't already in disasm
            if rep_cmt and rep_cmt not in disasm:
                line += f"    ; {rep_cmt}"
            elif cmt and cmt not in disasm:
                line += f"    ; {cmt}"
            
            lines.append(line)
        
        # Get posterior (after) comments
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
    """Get the decompiled pseudocode for a function."""
    if not _hexrays_ready():
        return None
    
    try:
        cf = ida_hexrays.decompile(ea)
        if not cf:
            return None
        return _pseudocode_text(cf)
    except Exception:
        return None

def copy_to_clipboard(text):
    """Copy text to system clipboard using safe Win32 API."""
    try:
        import ctypes
        from ctypes import wintypes
        
        # Proper Win32 function signatures
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        
        # Set proper return/arg types to avoid access violations
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
        
        # Encode text
        if isinstance(text, str):
            data = text.encode('utf-16le') + b'\x00\x00'
        else:
            data = str(text).encode('utf-16le') + b'\x00\x00'
        
        # Open clipboard
        if not user32.OpenClipboard(None):
            idaapi.msg(f"[{PLUGIN_NAME}] Failed to open clipboard\n")
            return False
        
        try:
            user32.EmptyClipboard()
            
            # Allocate global memory
            hMem = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data))
            if not hMem:
                idaapi.msg(f"[{PLUGIN_NAME}] Failed to allocate clipboard memory\n")
                return False
            
            # Lock and copy
            pMem = kernel32.GlobalLock(hMem)
            if not pMem:
                idaapi.msg(f"[{PLUGIN_NAME}] Failed to lock clipboard memory\n")
                return False
            
            ctypes.memmove(pMem, data, len(data))
            kernel32.GlobalUnlock(hMem)
            
            # Set clipboard data (clipboard now owns the memory)
            if not user32.SetClipboardData(CF_UNICODETEXT, hMem):
                idaapi.msg(f"[{PLUGIN_NAME}] Failed to set clipboard data\n")
                return False
            
            return True
        finally:
            user32.CloseClipboard()
            
    except Exception as e:
        idaapi.msg(f"[{PLUGIN_NAME}] Clipboard error: {e}\n")
        traceback.print_exc()
        return False

# ============================================================================
# DUMP ALL FUNCTIONS
# ============================================================================

def dump_all_assembly():
    """Dump ALL functions to a single .asm assembly file"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_ASSEMBLY.asm")
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all assembly to: {filepath}\n")
    
    # Collect function list first
    func_list = list(idautils.Functions())
    total = len(func_list)
    success = 0
    
    all_asm = []
    all_asm.append(";" + "=" * 79)
    all_asm.append("; ALL ASSEMBLY DUMP")
    all_asm.append("; Total functions: " + str(total))
    all_asm.append(";" + "=" * 79)
    all_asm.append("")
    
    # Show wait dialog
    ida_kernwin.show_wait_box(f"Dumping assembly... 0/{total}")
    
    try:
        for i, func_ea in enumerate(func_list):
            # Check for user cancel
            if ida_kernwin.user_cancelled():
                idaapi.msg(f"[{PLUGIN_NAME}] Cancelled by user\n")
                break
            
            # Update progress every 50 functions
            if i % 50 == 0:
                ida_kernwin.replace_wait_box(f"Dumping assembly... {i}/{total} ({success} written)")
            
            func_name = idc.get_func_name(func_ea) or f"func_{func_ea:X}"
            
            asm = get_function_assembly(func_ea)
            if asm:
                all_asm.append(";" + "-" * 79)
                all_asm.append(asm)
                all_asm.append("")
                success += 1
    finally:
        ida_kernwin.hide_wait_box()
    
    all_asm.append("")
    all_asm.append(f"; Dump complete: {success}/{total} functions")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(all_asm))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Assembly dump complete: {success}/{total} functions\n")
    idaapi.msg(f"[{PLUGIN_NAME}] Output: {filepath}\n")

def dump_all_decompiled():
    """Dump ALL functions to a single .c decompiled file"""
    if not _hexrays_ready():
        idaapi.msg(f"[{PLUGIN_NAME}] Hex-Rays decompiler not available!\n")
        return
    
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_DECOMPILED.c")
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all decompiled to: {filepath}\n")
    
    # Collect function list first
    func_list = list(idautils.Functions())
    total = len(func_list)
    success = failed = 0
    
    # Show wait dialog
    ida_kernwin.show_wait_box(f"Decompiling... 0/{total}")
    
    try:
        # Write directly to file for better performance
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("/" + "*" * 78 + "/\n")
            f.write("/* ALL DECOMPILED DUMP */\n")
            f.write(f"/* Total functions: {total} */\n")
            f.write("/" + "*" * 78 + "/\n\n")
            
            for i, func_ea in enumerate(func_list):
                # Check for user cancel
                if ida_kernwin.user_cancelled():
                    idaapi.msg(f"[{PLUGIN_NAME}] Cancelled by user\n")
                    break
                
                # Update progress every 50 functions
                if i % 50 == 0:
                    ida_kernwin.replace_wait_box(f"Decompiling... {i}/{total} ({success} ok, {failed} failed)")
                
                func_name = idc.get_func_name(func_ea) or f"func_{func_ea:X}"
                
                try:
                    decompiled = get_function_decompiled(func_ea)
                    if decompiled:
                        f.write("/" + "-" * 78 + "/\n")
                        f.write(f"// Function: {func_name}\n")
                        f.write(f"// Address: 0x{func_ea:X}\n\n")
                        f.write(decompiled)
                        f.write("\n\n")
                        success += 1
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
            
            f.write(f"\n/* Dump complete: {success}/{total} functions ({failed} failed) */\n")
    finally:
        ida_kernwin.hide_wait_box()
    
    idaapi.msg(f"[{PLUGIN_NAME}] Decompiled dump complete: {success}/{total} functions ({failed} failed)\n")
    idaapi.msg(f"[{PLUGIN_NAME}] Output: {filepath}\n")

def dump_all_strings():
    """Dump ALL strings to a single .txt file"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_STRINGS.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all strings to: {filepath}\n")
    
    # Show wait dialog
    ida_kernwin.show_wait_box("Collecting strings...")
    
    strings = []
    strings.append("=" * 80)
    strings.append("ALL STRINGS DUMP")
    strings.append("=" * 80)
    strings.append("")
    
    count = 0
    try:
        for s in idautils.Strings():
            # Check for user cancel every 5000 strings
            if count % 5000 == 0:
                if ida_kernwin.user_cancelled():
                    idaapi.msg(f"[{PLUGIN_NAME}] Cancelled by user\n")
                    break
                ida_kernwin.replace_wait_box(f"Collecting strings... {count}")
            
            count += 1
            addr = s.ea
            length = s.length
            str_type = s.strtype
            
            try:
                content = idc.get_strlit_contents(addr, length, str_type)
                if content:
                    if isinstance(content, bytes):
                        try:
                            content = content.decode('utf-8', errors='replace')
                        except:
                            content = content.decode('latin-1', errors='replace')
                    
                    seg_name = idc.get_segm_name(addr) or "unknown"
                    strings.append(f"{seg_name}:{addr:016X}\t{length:04d}\t{content}")
            except Exception:
                pass
    finally:
        ida_kernwin.hide_wait_box()
    
    strings.append("")
    strings.append(f"Total strings: {count}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(strings))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Strings dump complete: {count} strings\n")
    idaapi.msg(f"[{PLUGIN_NAME}] Output: {filepath}\n")

def dump_all_names():
    """Dump ALL named addresses (functions, globals, labels)"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_NAMES.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all names to: {filepath}\n")
    ida_kernwin.show_wait_box("Collecting names...")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL NAMES DUMP")
    lines.append("=" * 80)
    lines.append("")
    
    count = 0
    try:
        for ea, name in idautils.Names():
            if count % 5000 == 0:
                if ida_kernwin.user_cancelled():
                    break
                ida_kernwin.replace_wait_box(f"Collecting names... {count}")
            
            count += 1
            seg_name = idc.get_segm_name(ea) or "unknown"
            flags = idc.get_full_flags(ea)
            
            # Determine type
            if idc.is_code(flags):
                item_type = "CODE"
            elif idc.is_data(flags):
                item_type = "DATA"
            else:
                item_type = "UNKN"
            
            lines.append(f"{seg_name}:{ea:016X}\t{item_type}\t{name}")
    finally:
        ida_kernwin.hide_wait_box()
    
    lines.append("")
    lines.append(f"Total names: {count}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Names dump complete: {count} names\n")

def dump_all_imports():
    """Dump ALL imported functions"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_IMPORTS.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all imports to: {filepath}\n")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL IMPORTS DUMP")
    lines.append("=" * 80)
    lines.append("")
    
    count = 0
    nimps = idaapi.get_import_module_qty()
    
    for i in range(nimps):
        module_name = idaapi.get_import_module_name(i)
        if not module_name:
            module_name = f"module_{i}"
        
        lines.append(f"\n[MODULE] {module_name}")
        lines.append("-" * 60)
        
        def imp_cb(ea, name, ordinal):
            nonlocal count
            count += 1
            if name:
                lines.append(f"  {ea:016X}\t{name}")
            else:
                lines.append(f"  {ea:016X}\tordinal_{ordinal}")
            return True
        
        idaapi.enum_import_names(i, imp_cb)
    
    lines.append("")
    lines.append(f"Total imports: {count}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Imports dump complete: {count} imports from {nimps} modules\n")

def dump_all_exports():
    """Dump ALL exported functions"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_EXPORTS.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all exports to: {filepath}\n")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL EXPORTS DUMP")
    lines.append("=" * 80)
    lines.append("")
    
    count = 0
    for entry in idautils.Entries():
        count += 1
        # Entries() returns (index, ordinal, ea, name)
        idx, ordinal, ea, name = entry
        lines.append(f"{ea:016X}\tord:{ordinal}\t{name}")
    
    lines.append("")
    lines.append(f"Total exports: {count}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Exports dump complete: {count} exports\n")

def dump_all_segments():
    """Dump ALL segment information"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_SEGMENTS.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all segments to: {filepath}\n")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL SEGMENTS DUMP")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"{'Name':<20} {'Start':>18} {'End':>18} {'Size':>12} {'Class':<10} {'Perms'}")
    lines.append("-" * 100)
    
    count = 0
    for seg_ea in idautils.Segments():
        count += 1
        seg = idaapi.getseg(seg_ea)
        if seg:
            name = idc.get_segm_name(seg_ea) or "unknown"
            start = seg.start_ea
            end = seg.end_ea
            size = end - start
            sclass = idaapi.get_segm_class(seg) or ""
            
            perms = ""
            if seg.perm & idaapi.SEGPERM_READ:
                perms += "R"
            if seg.perm & idaapi.SEGPERM_WRITE:
                perms += "W"
            if seg.perm & idaapi.SEGPERM_EXEC:
                perms += "X"
            
            lines.append(f"{name:<20} {start:018X} {end:018X} {size:>12} {sclass:<10} {perms}")
    
    lines.append("")
    lines.append(f"Total segments: {count}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Segments dump complete: {count} segments\n")

def dump_all_vtables():
    """Dump ALL vtables (virtual function tables) by finding RTTI patterns"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_VTABLES.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Scanning for vtables...\n")
    ida_kernwin.show_wait_box("Scanning for vtables...")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL VTABLES DUMP (RTTI-based)")
    lines.append("=" * 80)
    lines.append("")
    
    vtables = []
    count = 0
    
    try:
        # Search for RTTI type descriptors (.?AV pattern for MSVC)
        # These indicate C++ classes with vtables
        for ea, name in idautils.Names():
            if count % 10000 == 0:
                if ida_kernwin.user_cancelled():
                    break
                ida_kernwin.replace_wait_box(f"Scanning... {count} names checked, {len(vtables)} vtables found")
            count += 1
            
            # MSVC RTTI type descriptor pattern
            if name.startswith("??_R0") or ".?AV" in name or ".?AU" in name:
                # Get class name from RTTI
                class_name = name
                if ".?AV" in name:
                    # Extract class name: .?AVClassName@@
                    match = re.search(r'\.?\?AV([^@]+)@@', name)
                    if match:
                        class_name = match.group(1)
                elif ".?AU" in name:
                    # Struct: .?AUStructName@@
                    match = re.search(r'\.?\?AU([^@]+)@@', name)
                    if match:
                        class_name = match.group(1)
                
                vtables.append((ea, name, class_name))
        
        # Also search for vtable symbols directly
        for ea, name in idautils.Names():
            if "vftable" in name.lower() or "vtbl" in name.lower() or name.startswith("??_7"):
                # MSVC vtable pattern ??_7ClassName@@6B@
                class_name = name
                match = re.search(r'\?\?_7([^@]+)@@', name)
                if match:
                    class_name = match.group(1)
                
                # Get vtable entries
                vtables.append((ea, name, class_name))
    finally:
        ida_kernwin.hide_wait_box()
    
    # Sort by class name
    vtables.sort(key=lambda x: x[2])
    
    # Write vtables
    current_class = None
    for ea, full_name, class_name in vtables:
        if class_name != current_class:
            lines.append("")
            lines.append(f"[CLASS] {class_name}")
            lines.append("-" * 60)
            current_class = class_name
        
        lines.append(f"  {ea:016X}\t{full_name}")
        
        # If this looks like a vtable, try to dump entries
        if "vftable" in full_name.lower() or "vtbl" in full_name.lower() or full_name.startswith("??_7"):
            # Read vtable entries (function pointers)
            entry_ea = ea
            entry_count = 0
            while entry_count < 100:  # Limit to 100 entries
                ptr = idc.get_qword(entry_ea) if idaapi.inf_is_64bit() else idc.get_wide_dword(entry_ea)
                if ptr == 0 or ptr == idaapi.BADADDR:
                    break
                
                # Check if it points to code
                if idc.is_code(idc.get_full_flags(ptr)):
                    func_name = idc.get_func_name(ptr) or f"sub_{ptr:X}"
                    lines.append(f"    [{entry_count}] {ptr:016X} -> {func_name}")
                    entry_count += 1
                    entry_ea += 8 if idaapi.inf_is_64bit() else 4
                else:
                    break
    
    lines.append("")
    lines.append(f"Total RTTI/vtable entries: {len(vtables)}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] VTables dump complete: {len(vtables)} entries\n")

def dump_all_rtti():
    """Dump ALL RTTI (Runtime Type Information) - class names and hierarchy"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_RTTI.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Scanning for RTTI...\n")
    ida_kernwin.show_wait_box("Scanning for RTTI...")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL RTTI DUMP (C++ Class Information)")
    lines.append("=" * 80)
    lines.append("")
    
    classes = {}
    count = 0
    
    try:
        for ea, name in idautils.Names():
            if count % 10000 == 0:
                if ida_kernwin.user_cancelled():
                    break
                ida_kernwin.replace_wait_box(f"Scanning RTTI... {count}")
            count += 1
            
            # Type descriptors
            if ".?AV" in name or ".?AU" in name:
                # Extract full class name with namespaces
                match = re.search(r'\.?\?A[VU](.+?)@@', name)
                if match:
                    raw_name = match.group(1)
                    # Demangle namespace separators
                    class_name = raw_name.replace("@", "::")
                    if class_name not in classes:
                        classes[class_name] = {'type_desc': [], 'vtables': [], 'base_classes': []}
                    classes[class_name]['type_desc'].append(ea)
            
            # Base class descriptors (inheritance info)
            elif "??_R1" in name:
                # ??_R1A@?0A@EA@ClassName@@8
                match = re.search(r'\?\?_R1.+?@(.+?)@@', name)
                if match:
                    class_name = match.group(1).replace("@", "::")
                    if class_name not in classes:
                        classes[class_name] = {'type_desc': [], 'vtables': [], 'base_classes': []}
                    classes[class_name]['base_classes'].append((ea, name))
            
            # VTables
            elif name.startswith("??_7"):
                match = re.search(r'\?\?_7(.+?)@@', name)
                if match:
                    class_name = match.group(1).replace("@", "::")
                    if class_name not in classes:
                        classes[class_name] = {'type_desc': [], 'vtables': [], 'base_classes': []}
                    classes[class_name]['vtables'].append(ea)
    finally:
        ida_kernwin.hide_wait_box()
    
    # Write sorted by class name
    for class_name in sorted(classes.keys()):
        info = classes[class_name]
        lines.append(f"\n[CLASS] {class_name}")
        lines.append("-" * 60)
        
        if info['type_desc']:
            lines.append(f"  Type Descriptors:")
            for ea in info['type_desc']:
                lines.append(f"    {ea:016X}")
        
        if info['vtables']:
            lines.append(f"  VTables:")
            for ea in info['vtables']:
                lines.append(f"    {ea:016X}")
        
        if info['base_classes']:
            lines.append(f"  Base Class Info:")
            for ea, name in info['base_classes']:
                lines.append(f"    {ea:016X} {name}")
    
    lines.append("")
    lines.append(f"Total classes found: {len(classes)}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] RTTI dump complete: {len(classes)} classes\n")

def dump_all_xrefs():
    """Dump cross-references for all functions"""
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_XREFS.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all xrefs...\n")
    ida_kernwin.show_wait_box("Collecting xrefs...")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL CROSS-REFERENCES DUMP")
    lines.append("=" * 80)
    lines.append("")
    
    func_list = list(idautils.Functions())
    total = len(func_list)
    
    try:
        for i, func_ea in enumerate(func_list):
            if i % 500 == 0:
                if ida_kernwin.user_cancelled():
                    break
                ida_kernwin.replace_wait_box(f"Collecting xrefs... {i}/{total}")
            
            func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
            
            # Get callers (who calls this function)
            callers = []
            for xref in idautils.XrefsTo(func_ea):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    caller_name = idc.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:X}"
                    callers.append((xref.frm, caller_name))
            
            # Get callees (who this function calls)
            callees = []
            func = ida_funcs.get_func(func_ea)
            if func:
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    for xref in idautils.XrefsFrom(head):
                        if xref.type in [idaapi.fl_CF, idaapi.fl_CN]:
                            callee_name = idc.get_func_name(xref.to) or f"sub_{xref.to:X}"
                            callees.append((xref.to, callee_name))
            
            if callers or callees:
                lines.append(f"\n[FUNC] {func_name} (0x{func_ea:X})")
                if callers:
                    lines.append(f"  Called by ({len(callers)}):")
                    for addr, name in callers[:20]:  # Limit to 20
                        lines.append(f"    {addr:016X} {name}")
                    if len(callers) > 20:
                        lines.append(f"    ... and {len(callers)-20} more")
                if callees:
                    # Deduplicate
                    unique_callees = list(set(callees))
                    lines.append(f"  Calls ({len(unique_callees)}):")
                    for addr, name in unique_callees[:20]:
                        lines.append(f"    {addr:016X} {name}")
                    if len(unique_callees) > 20:
                        lines.append(f"    ... and {len(unique_callees)-20} more")
    finally:
        ida_kernwin.hide_wait_box()
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Xrefs dump complete\n")

def dump_all_structures():
    """Dump ALL defined structures/types"""
    import ida_struct
    import ida_typeinf
    
    outdir = ensure_output_dir()
    filepath = os.path.join(outdir, "ALL_STRUCTURES.txt")
    
    idaapi.msg(f"[{PLUGIN_NAME}] Dumping all structures...\n")
    
    lines = []
    lines.append("=" * 80)
    lines.append("ALL STRUCTURES DUMP")
    lines.append("=" * 80)
    lines.append("")
    
    count = 0
    idx = idc.get_first_struc_idx()
    while idx != idaapi.BADADDR:
        count += 1
        sid = idc.get_struc_by_idx(idx)
        name = idc.get_struc_name(sid)
        size = idc.get_struc_size(sid)
        
        lines.append(f"\n[STRUCT] {name} (size: {size} bytes)")
        lines.append("-" * 60)
        
        # Get struct members
        sptr = ida_struct.get_struc(sid)
        if sptr:
            for i in range(sptr.memqty):
                member = sptr.get_member(i)
                if member:
                    mname = ida_struct.get_member_name(member.id)
                    moff = member.soff
                    msize = ida_struct.get_member_size(member)
                    lines.append(f"  +0x{moff:04X} {mname} ({msize} bytes)")
        
        idx = idc.get_next_struc_idx(idx)
    
    lines.append("")
    lines.append(f"Total structures: {count}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Structures dump complete: {count} structures\n")

def dump_everything():
    """Dump ALL: assembly + decompiled + strings + metadata"""
    idaapi.msg(f"[{PLUGIN_NAME}] === DUMPING EVERYTHING ===\n")
    
    dump_funcs = [
        ("Segments", dump_all_segments),
        ("Strings", dump_all_strings),
        ("Names", dump_all_names),
        ("Imports", dump_all_imports),
        ("Exports", dump_all_exports),
        ("Structures", dump_all_structures),
        ("RTTI", dump_all_rtti),
        ("VTables", dump_all_vtables),
        ("Assembly", dump_all_assembly),
        ("Xrefs", dump_all_xrefs),
    ]
    
    failed = []
    for name, func in dump_funcs:
        try:
            func()
        except Exception as e:
            idaapi.msg(f"[{PLUGIN_NAME}] ERROR dumping {name}: {e}\n")
            failed.append(name)
    
    # Decompiled requires Hex-Rays
    if _hexrays_ready():
        try:
            dump_all_decompiled()
        except Exception as e:
            idaapi.msg(f"[{PLUGIN_NAME}] ERROR dumping Decompiled: {e}\n")
            failed.append("Decompiled")
    
    if failed:
        idaapi.msg(f"[{PLUGIN_NAME}] === COMPLETE (with {len(failed)} errors: {', '.join(failed)}) ===\n")
    else:
        idaapi.msg(f"[{PLUGIN_NAME}] === COMPLETE ===\n")

# ============================================================================
# RIGHT-CLICK MENU ACTIONS
# ============================================================================

def get_selected_func_ea():
    """Get function EA from current context (works in disasm, pseudocode, and functions view)"""
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        return func.start_ea
    # If no function at cursor, maybe we're in functions list - ea might be the function itself
    if idc.get_func_name(ea):
        return ea
    return None

def get_selected_string():
    """Get string content and address from current cursor position"""
    ea = idc.get_screen_ea()
    str_type = idc.get_str_type(ea)
    if str_type is not None and str_type >= 0:
        content = idc.get_strlit_contents(ea, -1, str_type)
        if content:
            if isinstance(content, bytes):
                try:
                    content = content.decode('utf-8', errors='replace')
                except:
                    content = content.decode('latin-1', errors='replace')
            return (ea, content)
    return None

def dump_string_xrefs(str_ea, str_content):
    """Dump all xrefs to a string (who references it)"""
    # Create safe filename from string content
    safe_content = sanitize_filename(str_content[:50]) if str_content else f"str_{str_ea:X}"
    
    outdir = ensure_output_dir("string_xrefs")
    filepath = os.path.join(outdir, f"{safe_content}_xrefs.txt")
    
    lines = []
    lines.append("=" * 80)
    lines.append(f"XREFS TO STRING")
    lines.append(f"Address: 0x{str_ea:X}")
    lines.append(f"Content: \"{str_content[:200]}{'...' if len(str_content) > 200 else ''}\"")
    lines.append("=" * 80)
    lines.append("")
    
    # Get all references to this string
    lines.append("[REFERENCED BY]")
    lines.append("-" * 60)
    
    refs = []
    for xref in idautils.XrefsTo(str_ea):
        ref_func = ida_funcs.get_func(xref.frm)
        if ref_func:
            func_name = idc.get_func_name(ref_func.start_ea) or f"sub_{ref_func.start_ea:X}"
            refs.append((xref.frm, func_name, ref_func.start_ea))
        else:
            # Reference from data, not code
            name = idc.get_name(xref.frm) or f"data_{xref.frm:X}"
            refs.append((xref.frm, name, None))
    
    # Group by function
    func_refs = {}
    data_refs = []
    for addr, name, func_start in refs:
        if func_start:
            if func_start not in func_refs:
                func_refs[func_start] = {'name': name, 'addrs': []}
            func_refs[func_start]['addrs'].append(addr)
        else:
            data_refs.append((addr, name))
    
    if func_refs:
        lines.append("\nFunctions:")
        for func_start, info in sorted(func_refs.items(), key=lambda x: x[0]):
            lines.append(f"  {func_start:016X}  {info['name']}")
            for addr in info['addrs']:
                lines.append(f"    -> ref at {addr:016X}")
    
    if data_refs:
        lines.append("\nData references:")
        for addr, name in data_refs:
            lines.append(f"  {addr:016X}  {name}")
    
    lines.append("")
    lines.append(f"Total references: {len(refs)} ({len(func_refs)} functions, {len(data_refs)} data)")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] String xrefs saved to: {filepath}\n")
    return filepath

def copy_string_to_clipboard(str_ea, str_content):
    """Copy string info to clipboard"""
    text = f"String at 0x{str_ea:X}:\n\"{str_content}\""
    if copy_to_clipboard(text):
        idaapi.msg(f"[{PLUGIN_NAME}] String copied to clipboard\n")

def get_function_strings(func_ea):
    """Get all strings referenced by a function"""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    
    strings = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head):
            # Check if target is a string
            str_type = idc.get_str_type(xref.to)
            if str_type is not None and str_type >= 0:
                content = idc.get_strlit_contents(xref.to, -1, str_type)
                if content:
                    if isinstance(content, bytes):
                        try:
                            content = content.decode('utf-8', errors='replace')
                        except:
                            content = content.decode('latin-1', errors='replace')
                    strings.append((xref.to, content))
    
    # Deduplicate
    seen = set()
    unique = []
    for addr, s in strings:
        if addr not in seen:
            seen.add(addr)
            unique.append((addr, s))
    return unique

def dump_function_xrefs(func_ea):
    """Dump xrefs for a single function"""
    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
    safe_name = sanitize_filename(func_name)
    
    outdir = ensure_output_dir("function_xrefs")
    filepath = os.path.join(outdir, f"{safe_name}_xrefs.txt")
    
    lines = []
    lines.append("=" * 80)
    lines.append(f"XREFS FOR: {func_name}")
    lines.append(f"Address: 0x{func_ea:X}")
    lines.append("=" * 80)
    lines.append("")
    
    # Get strings in this function
    func_strings = get_function_strings(func_ea)
    if func_strings:
        lines.append("[STRINGS]")
        lines.append("-" * 40)
        for addr, s in func_strings:
            # Escape newlines for display
            s_escaped = s.replace('\n', '\\n').replace('\r', '\\r')
            if len(s_escaped) > 100:
                s_escaped = s_escaped[:97] + "..."
            lines.append(f"  {addr:016X}  \"{s_escaped}\"")
        lines.append(f"Total strings: {len(func_strings)}")
        lines.append("")
    
    # Get callers (who calls this function)
    lines.append("[CALLED BY]")
    lines.append("-" * 40)
    callers = []
    for xref in idautils.XrefsTo(func_ea):
        caller_func = ida_funcs.get_func(xref.frm)
        if caller_func:
            caller_name = idc.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:X}"
            callers.append((xref.frm, caller_name, caller_func.start_ea))
    
    # Deduplicate by caller function
    seen = set()
    for addr, name, func_start in callers:
        if func_start not in seen:
            seen.add(func_start)
            lines.append(f"  {addr:016X}  {name}")
    lines.append(f"Total callers: {len(seen)}")
    lines.append("")
    
    # Get callees (who this function calls)
    lines.append("[CALLS]")
    lines.append("-" * 40)
    callees = []
    func = ida_funcs.get_func(func_ea)
    if func:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head):
                if xref.type in [idaapi.fl_CF, idaapi.fl_CN]:
                    callee_name = idc.get_func_name(xref.to) or f"sub_{xref.to:X}"
                    callees.append((xref.to, callee_name))
    
    # Deduplicate
    seen = set()
    for addr, name in callees:
        if addr not in seen:
            seen.add(addr)
            lines.append(f"  {addr:016X}  {name}")
    lines.append(f"Total calls: {len(seen)}")
    lines.append("")
    
    # Data references
    lines.append("[DATA REFS FROM]")
    lines.append("-" * 40)
    data_refs = []
    if func:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head):
                if xref.type in [idaapi.dr_O, idaapi.dr_R, idaapi.dr_W]:
                    ref_name = idc.get_name(xref.to) or f"data_{xref.to:X}"
                    data_refs.append((xref.to, ref_name))
    
    seen = set()
    for addr, name in data_refs:
        if addr not in seen:
            seen.add(addr)
            lines.append(f"  {addr:016X}  {name}")
    lines.append(f"Total data refs: {len(seen)}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Xrefs for {func_name} saved to: {filepath}\n")
    return filepath

def dump_function_all(func_ea):
    """Dump everything for a single function (asm, decompiled, xrefs)"""
    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
    safe_name = sanitize_filename(func_name)
    
    outdir = ensure_output_dir("function_dumps")
    filepath = os.path.join(outdir, f"{safe_name}_full.txt")
    
    lines = []
    lines.append("=" * 80)
    lines.append(f"FULL DUMP: {func_name}")
    lines.append(f"Address: 0x{func_ea:X}")
    lines.append("=" * 80)
    lines.append("")
    
    # Assembly
    lines.append("=" * 40 + " ASSEMBLY " + "=" * 40)
    asm = get_function_assembly(func_ea)
    lines.append(asm if asm else "; Failed to get assembly")
    lines.append("")
    
    # Decompiled
    lines.append("=" * 40 + " DECOMPILED " + "=" * 40)
    decompiled = get_function_decompiled(func_ea)
    lines.append(decompiled if decompiled else "// Decompilation not available")
    lines.append("")
    
    # Strings
    lines.append("=" * 40 + " STRINGS " + "=" * 40)
    func_strings = get_function_strings(func_ea)
    if func_strings:
        for addr, s in func_strings:
            s_escaped = s.replace('\n', '\\n').replace('\r', '\\r')
            if len(s_escaped) > 100:
                s_escaped = s_escaped[:97] + "..."
            lines.append(f"  {addr:016X}  \"{s_escaped}\"")
        lines.append(f"Total: {len(func_strings)} strings")
    else:
        lines.append("  (no strings found)")
    lines.append("")
    
    # Xrefs
    lines.append("=" * 40 + " XREFS " + "=" * 40)
    
    # Callers
    lines.append("\n[CALLED BY]")
    callers = []
    for xref in idautils.XrefsTo(func_ea):
        caller_func = ida_funcs.get_func(xref.frm)
        if caller_func:
            caller_name = idc.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:X}"
            callers.append((xref.frm, caller_name, caller_func.start_ea))
    
    seen = set()
    for addr, name, func_start in callers:
        if func_start not in seen:
            seen.add(func_start)
            lines.append(f"  {addr:016X}  {name}")
    
    # Callees
    lines.append("\n[CALLS]")
    callees = []
    func = ida_funcs.get_func(func_ea)
    if func:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head):
                if xref.type in [idaapi.fl_CF, idaapi.fl_CN]:
                    callee_name = idc.get_func_name(xref.to) or f"sub_{xref.to:X}"
                    callees.append((xref.to, callee_name))
    
    seen = set()
    for addr, name in callees:
        if addr not in seen:
            seen.add(addr)
            lines.append(f"  {addr:016X}  {name}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    idaapi.msg(f"[{PLUGIN_NAME}] Full dump for {func_name} saved to: {filepath}\n")
    return filepath

class CopyAssemblyAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            idaapi.msg(f"[{PLUGIN_NAME}] No function at current address\n")
            return 1
        
        asm = get_function_assembly(func.start_ea)
        if asm and copy_to_clipboard(asm):
            func_name = idc.get_func_name(func.start_ea) or f"func_{func.start_ea:X}"
            idaapi.msg(f"[{PLUGIN_NAME}] Copied assembly for {func_name}\n")
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE

class CopyDecompiledAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            idaapi.msg(f"[{PLUGIN_NAME}] No function at current address\n")
            return 1
        
        func_name = idc.get_func_name(func.start_ea) or f"func_{func.start_ea:X}"
        decompiled = get_function_decompiled(func.start_ea)
        if decompiled:
            header = f"// Function: {func_name}\n// Address: 0x{func.start_ea:X}\n\n"
            if copy_to_clipboard(header + decompiled):
                idaapi.msg(f"[{PLUGIN_NAME}] Copied decompiled for {func_name}\n")
        else:
            idaapi.msg(f"[{PLUGIN_NAME}] Failed to decompile (Hex-Rays required)\n")
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE] else idaapi.AST_DISABLE

class CopyAllAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            idaapi.msg(f"[{PLUGIN_NAME}] No function at current address\n")
            return 1
        
        func_name = idc.get_func_name(func.start_ea) or f"func_{func.start_ea:X}"
        
        parts = []
        parts.append("=" * 80)
        parts.append(f"FUNCTION: {func_name} (0x{func.start_ea:X})")
        parts.append("=" * 80)
        parts.append("")
        parts.append("-" * 40 + " ASSEMBLY " + "-" * 40)
        asm = get_function_assembly(func.start_ea)
        parts.append(asm if asm else "; Failed to get assembly")
        parts.append("")
        parts.append("-" * 40 + " DECOMPILED " + "-" * 40)
        decompiled = get_function_decompiled(func.start_ea)
        parts.append(decompiled if decompiled else "// Failed to decompile")
        
        if copy_to_clipboard("\n".join(parts)):
            idaapi.msg(f"[{PLUGIN_NAME}] Copied ALL for {func_name}\n")
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE] else idaapi.AST_DISABLE

class DumpAllAssemblyAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_assembly()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpAllDecompiledAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_decompiled()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpAllStringsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_strings()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpEverythingAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_everything()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpNamesAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_names()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpImportsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_imports()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpExportsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_exports()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpSegmentsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_segments()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpVTablesAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_vtables()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpRTTIAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_rtti()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpXrefsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_xrefs()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DumpStructuresAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        dump_all_structures()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# Function-specific dump actions (for right-click on a function)
class DumpFunctionAssemblyAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_selected_func_ea()
        if not func_ea:
            idaapi.msg(f"[{PLUGIN_NAME}] No function selected\n")
            return 1
        
        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        safe_name = sanitize_filename(func_name)
        outdir = ensure_output_dir("function_dumps")
        filepath = os.path.join(outdir, f"{safe_name}.asm")
        
        asm = get_function_assembly(func_ea)
        if asm:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(asm)
            idaapi.msg(f"[{PLUGIN_NAME}] Assembly for {func_name} saved to: {filepath}\n")
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS]:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE

class DumpFunctionDecompiledAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_selected_func_ea()
        if not func_ea:
            idaapi.msg(f"[{PLUGIN_NAME}] No function selected\n")
            return 1
        
        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        safe_name = sanitize_filename(func_name)
        outdir = ensure_output_dir("function_dumps")
        filepath = os.path.join(outdir, f"{safe_name}.c")
        
        decompiled = get_function_decompiled(func_ea)
        if decompiled:
            header = f"// Function: {func_name}\n// Address: 0x{func_ea:X}\n\n"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(header + decompiled)
            idaapi.msg(f"[{PLUGIN_NAME}] Decompiled for {func_name} saved to: {filepath}\n")
        else:
            idaapi.msg(f"[{PLUGIN_NAME}] Failed to decompile {func_name}\n")
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS]:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE

class DumpFunctionXrefsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_selected_func_ea()
        if not func_ea:
            idaapi.msg(f"[{PLUGIN_NAME}] No function selected\n")
            return 1
        
        dump_function_xrefs(func_ea)
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS]:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE

class DumpFunctionAllAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_selected_func_ea()
        if not func_ea:
            idaapi.msg(f"[{PLUGIN_NAME}] No function selected\n")
            return 1
        
        dump_function_all(func_ea)
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS]:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE

# String-specific actions (for right-click on strings)
class CopyStringAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        str_info = get_selected_string()
        if not str_info:
            idaapi.msg(f"[{PLUGIN_NAME}] No string at current address\n")
            return 1
        
        str_ea, str_content = str_info
        copy_string_to_clipboard(str_ea, str_content)
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in [idaapi.BWN_STRINGS, idaapi.BWN_DISASM]:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE

class DumpStringXrefsAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        str_info = get_selected_string()
        if not str_info:
            idaapi.msg(f"[{PLUGIN_NAME}] No string at current address\n")
            return 1
        
        str_ea, str_content = str_info
        dump_string_xrefs(str_ea, str_content)
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in [idaapi.BWN_STRINGS, idaapi.BWN_DISASM]:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE

# ============================================================================
# HOOKS FOR RIGHT-CLICK MENU
# ============================================================================

class PopupHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        widget_type = idaapi.get_widget_type(widget)
        
        # Handle Strings view
        if widget_type == idaapi.BWN_STRINGS:
            str_info = get_selected_string()
            if str_info:
                str_ea, str_content = str_info
                # Truncate for display
                str_display = str_content[:40].replace('\n', '\\n').replace('\r', '\\r')
                if len(str_content) > 40:
                    str_display += "..."
                
                idaapi.update_action_label("dump:copy_string", f"Copy \"{str_display}\"")
                idaapi.update_action_label("dump:string_xrefs", f"Dump \"{str_display}\" Xrefs")
            
            idaapi.attach_action_to_popup(widget, popup, "dump:copy_string", None)
            idaapi.attach_action_to_popup(widget, popup, "dump:string_xrefs", None)
            
            # Also add Dump ALL submenu
            idaapi.attach_action_to_popup(widget, popup, "dump:all_strings", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        
        # Handle Names view
        if widget_type == idaapi.BWN_NAMES:
            # Add dump ALL options
            idaapi.attach_action_to_popup(widget, popup, "dump:all_names", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_strings", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        
        # Handle Imports view
        if widget_type == idaapi.BWN_IMPORTS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_imports", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        
        # Handle Exports view
        if widget_type == idaapi.BWN_EXPORTS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_exports", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        
        # Handle Segments view
        if widget_type == idaapi.BWN_SEGS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_segments", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        
        # Handle Structures view (BWN_STRUCTS renamed to BWN_LOCTYPS in IDA 9.x)
        BWN_STRUCTS = getattr(idaapi, 'BWN_STRUCTS', None) or getattr(idaapi, 'BWN_LOCTYPS', None)
        if BWN_STRUCTS is not None and widget_type == BWN_STRUCTS:
            idaapi.attach_action_to_popup(widget, popup, "dump:all_structures", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")
            return
        
        # Handle disassembly, pseudocode, and functions window
        if widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_FUNCS]:
            # Get function name for dynamic menu text
            func_ea = get_selected_func_ea()
            func_name = ""
            if func_ea:
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                # Truncate long names
                if len(func_name) > 40:
                    func_name = func_name[:37] + "..."
            
            # Update action names dynamically
            if func_name:
                # Copy actions
                idaapi.update_action_label("dump:copy_asm", f"Copy {func_name} Assembly")
                idaapi.update_action_label("dump:copy_decompiled", f"Copy {func_name} Decompiled")
                idaapi.update_action_label("dump:copy_all", f"Copy {func_name} (Asm+Decompiled)")
                # Dump actions
                idaapi.update_action_label("dump:func_asm", f"Dump {func_name} Assembly")
                idaapi.update_action_label("dump:func_decompiled", f"Dump {func_name} Decompiled")
                idaapi.update_action_label("dump:func_xrefs", f"Dump {func_name} Xrefs")
                idaapi.update_action_label("dump:func_all", f"Dump {func_name} (Full)")
            
            # Check if cursor is on a string in disasm view
            if widget_type == idaapi.BWN_DISASM:
                str_info = get_selected_string()
                if str_info:
                    str_ea, str_content = str_info
                    str_display = str_content[:30].replace('\n', '\\n').replace('\r', '\\r')
                    if len(str_content) > 30:
                        str_display += "..."
                    idaapi.update_action_label("dump:copy_string", f"Copy \"{str_display}\"")
                    idaapi.update_action_label("dump:string_xrefs", f"Dump \"{str_display}\" Xrefs")
                    idaapi.attach_action_to_popup(widget, popup, "dump:copy_string", None)
                    idaapi.attach_action_to_popup(widget, popup, "dump:string_xrefs", None)
            
            # Direct copy actions (disasm/pseudocode only)
            if widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE]:
                idaapi.attach_action_to_popup(widget, popup, "dump:copy_asm", None)
                idaapi.attach_action_to_popup(widget, popup, "dump:copy_decompiled", None)
                idaapi.attach_action_to_popup(widget, popup, "dump:copy_all", None)
            
            # Function-specific dump actions (submenu)
            idaapi.attach_action_to_popup(widget, popup, "dump:func_asm", "Dump Function/")
            idaapi.attach_action_to_popup(widget, popup, "dump:func_decompiled", "Dump Function/")
            idaapi.attach_action_to_popup(widget, popup, "dump:func_xrefs", "Dump Function/")
            idaapi.attach_action_to_popup(widget, popup, "dump:func_all", "Dump Function/")
            
            # Dump ALL submenu
            idaapi.attach_action_to_popup(widget, popup, "dump:all_asm", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_decompiled", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_strings", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_names", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_imports", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_exports", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_segments", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_vtables", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_rtti", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_xrefs", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:all_structures", "Dump ALL/")
            idaapi.attach_action_to_popup(widget, popup, "dump:everything", "Dump ALL/")

# ============================================================================
# PLUGIN CLASS
# ============================================================================

class DumpAllPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Dump ALL functions and strings"
    help = "Dumps all functions (asm/decompiled) and strings to files"
    wanted_name = "Dump All"
    wanted_hotkey = "Ctrl-Shift-D"
    
    popup_hooks = None

    def init(self):
        idaapi.msg(f"[{PLUGIN_NAME}] Initializing...\n")
        
        actions = [
            # Copy to clipboard actions
            ("dump:copy_asm", "Copy Assembly", CopyAssemblyAction(), "Ctrl-Shift-A"),
            ("dump:copy_decompiled", "Copy Decompiled (.c)", CopyDecompiledAction(), "Ctrl-Shift-C"),
            ("dump:copy_all", "Copy ALL (Asm+Decompiled)", CopyAllAction(), "Ctrl-Shift-X"),
            # String actions
            ("dump:copy_string", "Copy String", CopyStringAction(), ""),
            ("dump:string_xrefs", "Dump String Xrefs", DumpStringXrefsAction(), ""),
            # Function-specific dump actions
            ("dump:func_asm", "Dump Function Assembly", DumpFunctionAssemblyAction(), ""),
            ("dump:func_decompiled", "Dump Function Decompiled", DumpFunctionDecompiledAction(), ""),
            ("dump:func_xrefs", "Dump Function Xrefs", DumpFunctionXrefsAction(), ""),
            ("dump:func_all", "Dump Function (Full)", DumpFunctionAllAction(), ""),
            # Dump ALL actions
            ("dump:all_asm", "Dump ALL Assembly (.asm)", DumpAllAssemblyAction(), ""),
            ("dump:all_decompiled", "Dump ALL Decompiled (.c)", DumpAllDecompiledAction(), ""),
            ("dump:all_strings", "Dump ALL Strings", DumpAllStringsAction(), ""),
            ("dump:all_names", "Dump ALL Names", DumpNamesAction(), ""),
            ("dump:all_imports", "Dump ALL Imports", DumpImportsAction(), ""),
            ("dump:all_exports", "Dump ALL Exports", DumpExportsAction(), ""),
            ("dump:all_segments", "Dump ALL Segments", DumpSegmentsAction(), ""),
            ("dump:all_vtables", "Dump ALL VTables", DumpVTablesAction(), ""),
            ("dump:all_rtti", "Dump ALL RTTI", DumpRTTIAction(), ""),
            ("dump:all_xrefs", "Dump ALL Xrefs", DumpXrefsAction(), ""),
            ("dump:all_structures", "Dump ALL Structures", DumpStructuresAction(), ""),
            ("dump:everything", "Dump EVERYTHING", DumpEverythingAction(), ""),
        ]
        
        for action_id, action_name, handler, hotkey in actions:
            action_desc = idaapi.action_desc_t(action_id, action_name, handler, hotkey, action_name, -1)
            idaapi.register_action(action_desc)
        
        self.popup_hooks = PopupHooks()
        self.popup_hooks.hook()
        
        idaapi.msg(f"[{PLUGIN_NAME}] Ready! Right-click for options or Ctrl-Shift-D to dump everything.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        dump_everything()

    def term(self):
        if self.popup_hooks:
            self.popup_hooks.unhook()
        for action_id in ["dump:copy_asm", "dump:copy_decompiled", "dump:copy_all",
                          "dump:copy_string", "dump:string_xrefs",
                          "dump:func_asm", "dump:func_decompiled", "dump:func_xrefs", "dump:func_all",
                          "dump:all_asm", "dump:all_decompiled", "dump:all_strings",
                          "dump:all_names", "dump:all_imports", "dump:all_exports",
                          "dump:all_segments", "dump:all_vtables", "dump:all_rtti",
                          "dump:all_xrefs", "dump:all_structures", "dump:everything"]:
            idaapi.unregister_action(action_id)
        idaapi.msg(f"[{PLUGIN_NAME}] Terminated.\n")

def PLUGIN_ENTRY():
    return DumpAllPlugin()