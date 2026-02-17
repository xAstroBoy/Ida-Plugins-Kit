# IDA Pro 9.2 Python API — Complete Dumpable Data Reference

> **Comprehensive catalog of EVERY data type that can be extracted from an IDA database (.idb/.i64) using the Python SDK.**

---

## Table of Contents

1. [Database Metadata & Info](#1-database-metadata--info)
2. [Segments](#2-segments)
3. [Functions](#3-functions)
4. [Instructions & Disassembly](#4-instructions--disassembly)
5. [Bytes, Data & Raw Memory](#5-bytes-data--raw-memory)
6. [Names & Labels](#6-names--labels)
7. [Cross-References (Xrefs)](#7-cross-references-xrefs)
8. [Comments (All Types)](#8-comments-all-types)
9. [Strings](#9-strings)
10. [Type Information (Structs, Enums, Typedefs, Function Types)](#10-type-information)
11. [Entry Points (Exports)](#11-entry-points-exports)
12. [Imports](#12-imports)
13. [Stack Frames & Local Variables](#13-stack-frames--local-variables)
14. [Patches (Original vs Modified Bytes)](#14-patches)
15. [Hidden Ranges (Collapsed Areas)](#15-hidden-ranges)
16. [Bookmarks / Marked Positions](#16-bookmarks--marked-positions)
17. [Switch/Jump Tables](#17-switchjump-tables)
18. [Fixups / Relocations](#18-fixups--relocations)
19. [Try/Catch Exception Handlers](#19-trycatch-exception-handlers)
20. [Problems / Analysis Issues](#20-problems--analysis-issues)
21. [Segment Registers](#21-segment-registers)
22. [Operand Representation](#22-operand-representation)
23. [Reference Info (Offsets)](#23-reference-info-offsets)
24. [FLIRT / Library Signatures](#24-flirt--library-signatures)
25. [Additional Flags (aflags — Per-Address Metadata)](#25-additional-flags-aflags)
26. [Auto-Analysis State](#26-auto-analysis-state)
27. [Debugger Info (Stored in IDB)](#27-debugger-info-stored-in-idb)
28. [Custom Data Types & Formats](#28-custom-data-types--formats)
29. [Control Flow Graphs](#29-control-flow-graphs)
30. [Hex-Rays Decompiler Data](#30-hex-rays-decompiler-data)
31. [Color / Visual Info](#31-color--visual-info)
32. [Source File Mapping](#32-source-file-mapping)
33. [Processor-Specific Info](#33-processor-specific-info)
34. [Calling Conventions & Compiler Info](#34-calling-conventions--compiler-info)
35. [Register Value Tracking](#35-register-value-tracking)
36. [Address Mappings](#36-address-mappings)
37. [File Regions](#37-file-regions)
38. [Extra Lines (Anterior/Posterior)](#38-extra-lines-anteriorposterior)
39. [Encodings](#39-encodings)
40. [Search Functions](#40-search-functions)
41. [Utility Iterators (idautils)](#41-utility-iterators-idautils)
42. [Low-Level Database (Netnodes)](#42-low-level-database-netnodes)
43. [Directory Trees (Dirtree)](#43-directory-trees-dirtree)
44. [Selectors](#44-selectors)

---

## 1. Database Metadata & Info
**Module:** `ida_ida`, `ida_nalt`, `ida_loader`, `ida_idp`

| What | API Function |
|------|-------------|
| IDA version | `inf_get_version()` |
| Processor name | `inf_get_procname()`, `get_idp_name()` |
| File type (PE/ELF/etc.) | `inf_get_filetype()`, `get_file_type_name()` |
| OS type | `inf_get_ostype()` |
| App type | `inf_get_apptype()` |
| Bitness (16/32/64) | `inf_is_16bit()`, `inf_is_32bit_or_higher()`, `inf_is_64bit()`, `inf_get_app_bitness()` |
| Endianness | `inf_is_be()` |
| Is DLL | `inf_is_dll()` |
| Start EA (entry point) | `inf_get_start_ea()`, `inf_get_start_ip()` |
| Main address | `inf_get_main()` |
| Min/Max EA range | `inf_get_min_ea()`, `inf_get_max_ea()` |
| Original min/max EA | `inf_get_omin_ea()`, `inf_get_omax_ea()` |
| Image base | `get_imagebase()` |
| Database change count | `inf_get_database_change_count()` |
| IDB creation time | `get_idb_ctime()` |
| IDB open count | `get_idb_nopens()` |
| Initial IDA version | `get_initial_ida_version()` |
| Initial IDB version | `get_initial_idb_version()` |
| Elapsed analysis secs | `get_elapsed_secs()` |
| Input file path | `get_input_file_path()`, `dbg_get_input_path()` |
| Root filename | `get_root_filename()` |
| Input file size | `retrieve_input_file_size()` |
| Input file CRC32 | `retrieve_input_file_crc32()` |
| Input file MD5 | `retrieve_input_file_md5()` |
| Input file SHA256 | `retrieve_input_file_sha256()` |
| Loader format name | `get_loader_format_name()` |
| IDA notepad text | `get_ida_notepad_text()` |
| ASM include file | `get_asm_inc_file()` |
| Archive path | `get_archive_path()` |
| Source debug paths | `get_srcdbg_paths()` |
| ABI name | `get_abi_name()` |
| C header path | `get_c_header_path()` |
| C macros | `get_c_macros()` |
| GOT address | `get_gotea()` |
| Is trusted IDB | `is_trusted_idb()` |
| Analysis flags | `inf_get_af()`, `inf_get_af2()` |
| Low/high offset bounds | `inf_get_lowoff()`, `inf_get_highoff()` |
| String literal type | `inf_get_strtype()` |
| Compiler info | `inf_get_cc_id()`, `inf_get_cc_cm()`, `inf_get_callcnv()` |
| Type sizes (int/long/etc.) | `inf_get_cc_size_i()`, `inf_get_cc_size_b()`, `inf_get_cc_size_e()`, `inf_get_cc_size_s()`, `inf_get_cc_size_l()`, `inf_get_cc_size_ll()`, `inf_get_cc_size_ldbl()` |
| Private range | `inf_get_privrange()` |
| IDB directory | `GetIdbDir()` *(idautils)* |
| Paths (IDB, IDA, etc.) | `get_path(pt)` *(ida_loader)* |
| Kernel mode | `inf_is_kernel_mode()` |
| Database busy | `is_database_busy()` |
| Validate IDB integrity | `validate_idb()` |
| ELF debug file dir | `get_elf_debug_file_directory()` |
| Database contexts | `get_dbctx_id()`, `get_dbctx_qty()` |
| Pack mode | `inf_get_pack_mode()` |

---

## 2. Segments
**Module:** `ida_segment`, `idautils`

| What | API Function |
|------|-------------|
| Iterate all segments | `Segments()` *(idautils)*, `get_segm_qty()`, `getnseg(n)` |
| Get segment by EA | `getseg(ea)` |
| Get segment by name | `get_segm_by_name(name)` |
| Segment name | `get_segm_name(s)`, `get_visible_segm_name(s)` |
| Segment class | `get_segm_class(s)` |
| Segment type | `segtype(ea)` |
| Segment comment | `get_segment_cmt(s, repeatable)` |
| Segment base/para | `get_segm_base(s)`, `get_segm_para(s)` |
| Segment alignment | `get_segment_alignment(align)` |
| Segment combination | `get_segment_combination(comb)` |
| Segment bitness | `s.bitness` (0=16, 1=32, 2=64) |
| Segment permissions | `s.perm` (SFL_xxx flags) |
| Navigate segments | `get_first_seg()`, `get_last_seg()`, `get_next_seg(ea)`, `get_prev_seg(ea)` |
| Segment num | `get_segm_num(ea)` |
| Segment translations | `get_segment_translations(transmap, segstart)` |
| Is visible | `is_visible_segm(s)` |
| Is special segment | `is_spec_segm(seg_type)`, `is_spec_ea(ea)` |
| Default seg reg value | `get_defsr(s, reg)` |
| Group selector | `get_group_selector(grpsel)` |

---

## 3. Functions
**Module:** `ida_funcs`, `idautils`

| What | API Function |
|------|-------------|
| Iterate all functions | `Functions(start, end)` *(idautils)* |
| Function count | `get_func_qty()` |
| Get func by EA | `get_func(ea)` |
| Get func by index | `getn_func(n)` |
| Function name | `get_func_name(ea)` |
| Function comment | `get_func_cmt(pfn, repeatable)` |
| Function size | `calc_func_size(pfn)` |
| Function bitness | `get_func_bitness(pfn)` |
| Function ranges | `get_func_ranges(ranges, pfn)` |
| Function items (EAs) | `FuncItems(start)` *(idautils)* |
| Function chunks (tails) | `Chunks(start)` *(idautils)*, `get_fchunk(ea)`, `getn_fchunk(n)`, `get_fchunk_qty()` |
| Is entry/tail | `is_func_entry(pfn)`, `is_func_tail(pfn)` |
| Tail owners | `get_fchunk_referer(ea, idx)` |
| Navigate functions | `get_prev_func(ea)`, `get_next_func(ea)` |
| Thunk target | `calc_thunk_func_target(pfn)` |
| Does function return | `func_does_return(callee)` |
| Is visible | `is_visible_func(pfn)` |
| Function flags | `pfn.flags` (FUNC_NORET, FUNC_LIB, FUNC_STATIC, FUNC_FRAME, FUNC_THUNK, etc.) |
| Register arguments | `read_regargs(pfn)` |

---

## 4. Instructions & Disassembly
**Module:** `ida_ua`, `ida_lines`, `ida_idp`

| What | API Function |
|------|-------------|
| Decode instruction | `decode_insn(out, ea)`, `create_insn(ea)` |
| Decode previous insn | `decode_prev_insn(out, ea)`, `decode_preceding_insn(out, ea)` |
| Instruction mnemonic | `print_insn_mnem(ea)` |
| Print operand | `print_operand(ea, n)` |
| Full disassembly line | `generate_disasm_line(ea)`, `generate_disassembly(ea, ...)` *(ida_lines)* |
| Manual instruction override | `get_manual_insn(ea)`, `is_manual_insn(ea)` |
| Forced operand | `get_forced_operand(ea, n)`, `is_forced_operand(ea, n)` |
| Immediate values | `get_immvals(ea, n)`, `get_printable_immvals(ea, n)` |
| Is call/ret/jmp | `is_call_insn(insn)`, `is_ret_insn(insn)`, `is_indirect_jump_insn(insn)` |
| Is basic block end | `is_basic_block_end(insn)` |
| Is align instruction | `is_align_insn(ea)` |
| Iterate heads | `Heads(start, end)` *(idautils)* |
| Item navigation | `next_head(ea, max)`, `prev_head(ea, min)`, `get_item_head(ea)`, `get_item_end(ea)`, `get_item_size(ea)` |
| Operand info | `ph_get_operand_info(ea, n)` |
| Register names | `get_reg_name(reg, width)`, `ph_get_regnames()` |
| Instruction set | `GetInstructionList()`, `ph_get_instruc()` |

---

## 5. Bytes, Data & Raw Memory
**Module:** `ida_bytes`

| What | API Function |
|------|-------------|
| Read byte/word/dword/qword | `get_byte(ea)`, `get_word(ea)`, `get_dword(ea)`, `get_qword(ea)` |
| Read wide variants | `get_wide_byte(ea)`, `get_wide_word(ea)`, `get_wide_dword(ea)` |
| Read 16/32/64 bit | `get_16bit(ea)`, `get_32bit(ea)`, `get_64bit(ea)` |
| Read data value | `get_data_value(v, ea, size)` |
| Read bulk bytes | `get_bytes(ea, size)` |
| Read bytes with mask | `get_bytes_and_mask(ea, size)` |
| Get DB byte (internal) | `get_db_byte(ea)` |
| Flags at address | `get_flags(ea)`, `get_full_flags(ea)`, `get_flags_ex(ea, how)` |
| Item flag/refinfo | `get_item_flag(from, n, ea)`, `get_item_refinfo(ri, ea, n)` |
| Is mapped/loaded | `is_mapped(ea)`, `is_loaded(ea)` |
| Bits per unit | `nbits(ea)`, `bytesize(ea)` |
| Zero ranges | `get_zero_ranges(zranges, range)` |
| Is code/data/tail/unknown | `is_code(F)`, `is_data(F)`, `is_tail(F)`, `is_unknown(F)`, `is_head(F)` |
| Data type checks | `is_byte(F)`, `is_word(F)`, `is_dword(F)`, `is_qword(F)`, `is_oword(F)`, `is_yword(F)`, `is_zword(F)`, `is_tbyte(F)`, `is_float(F)`, `is_double(F)`, `is_pack_real(F)`, `is_strlit(F)`, `is_struct(F)`, `is_align(F)`, `is_custom(F)` |
| Data element size | `get_data_elsize(ea, F)`, `get_full_data_elsize(ea, F)` |
| Opinfo (struct/enum tid) | `get_opinfo(buf, ea, n, flags)` |
| String contents | `get_strlit_contents(ea, len, type)` |
| Max string length | `get_max_strlit_length(ea, strtype)` |
| Has value/name/xref/cmt | `has_value(F)`, `has_name(F)`, `has_xref(F)`, `has_cmt(F)`, `has_extra_cmts(F)`, `has_dummy_name(F)`, `has_auto_name(F)`, `has_any_name(F)`, `has_user_name(F)` |
| Operand type flags | `is_off(F,n)`, `is_char(F,n)`, `is_seg(F,n)`, `is_enum(F,n)`, `is_stroff(F,n)`, `is_stkvar(F,n)`, `is_fltnum(F,n)`, `is_custfmt(F,n)`, `is_numop(F,n)`, `is_defarg(F,n)` |
| Get enum applied to operand | `get_enum_id(ea, n)` |
| Sign/negation info | `is_invsign(ea, F, n)`, `is_bnot(ea, F, n)`, `is_lzero(ea, n)` |
| Suspicious operand | `is_suspop(ea, F, n)` |
| Radix | `get_radix(F, n)`, `get_default_radix()` |
| Has immediate | `has_immd(F)` |
| Is function start | `is_func(F)` |
| Is flow (from prev insn) | `is_flow(F)` |
| Struct offset path | `get_stroff_path(...)` |
| Find bytes/patterns | `find_byte(ea, ...)`, `find_bytes(bs, ...)`, `find_string(str, ...)`, `bin_search(...)`, `parse_binpat_str(...)` |
| Next/prev initialized | `next_inited(ea, max)`, `prev_inited(ea, min)` |
| Navigate items | `next_addr(ea)`, `prev_addr(ea)`, `next_chunk(ea)`, `prev_chunk(ea)`, `chunk_start(ea)`, `chunk_size(ea)` |
| Var-size item | `is_varsize_item(ea, F)`, `get_possible_item_varsize(ea, tif)` |

---

## 6. Names & Labels
**Module:** `ida_name`, `idautils`

| What | API Function |
|------|-------------|
| Iterate all names | `Names()` *(idautils)* |
| Get name at EA | `get_name(ea)`, `get_ea_name(ea)` |
| Get visible/short/long name | `get_visible_name(ea)`, `get_short_name(ea)`, `get_long_name(ea)` |
| Demangled name | `get_demangled_name(ea, ...)`, `demangle_name(name, ...)` |
| Colored names | `get_colored_name(ea)`, `get_colored_short_name(ea)`, `get_colored_long_name(ea)`, `get_nice_colored_name(ea)` |
| Name EA lookup | `get_name_ea(from, name)` |
| Name value | `get_name_value(from, name)` |
| Name color | `get_name_color(from, ea)` |
| Is public/weak | `is_public_name(ea)`, `is_weak_name(ea)` |
| Names list (nlist) | `get_nlist_size()`, `get_nlist_ea(idx)`, `get_nlist_name(idx)` |
| Debug names | `get_debug_names(...)`, `get_debug_name(ea_ptr, how)`, `get_debug_name_ea(name)` |
| Mangled name type | `get_mangled_name_type(name)` |
| Name expression | `get_name_expr(from, n, ea, off)` |
| Name base EA | `get_name_base_ea(from, to)` |

---

## 7. Cross-References (Xrefs)
**Module:** `ida_xref`, `idautils`

| What | API Function |
|------|-------------|
| Code refs TO | `CodeRefsTo(ea, flow)` *(idautils)* |
| Code refs FROM | `CodeRefsFrom(ea, flow)` *(idautils)* |
| Data refs TO | `DataRefsTo(ea)` *(idautils)* |
| Data refs FROM | `DataRefsFrom(ea)` *(idautils)* |
| All xrefs TO | `XrefsTo(ea, flags)` *(idautils)* |
| All xrefs FROM | `XrefsFrom(ea, flags)` *(idautils)* |
| First/next data ref FROM | `get_first_dref_from(frm)`, `get_next_dref_from(frm, current)` |
| First/next data ref TO | `get_first_dref_to(to)`, `get_next_dref_to(to, current)` |
| First/next code ref FROM | `get_first_cref_from(frm)`, `get_next_cref_from(frm, current)` |
| First/next code ref TO | `get_first_cref_to(to)`, `get_next_cref_to(to, current)` |
| Far code refs FROM/TO | `get_first_fcref_from(frm)`, `get_next_fcref_from(frm, current)`, `get_first_fcref_to(to)`, `get_next_fcref_to(to, current)` |
| Has external refs | `has_external_refs(pfn, ea)` |
| Has jump/flow xref | `has_jump_or_flow_xref(ea)` |
| Xref type name | `XrefTypeName(typecode)` *(idautils)* |
| Switch xrefs | `create_switch_xrefs(ea, si)`, `calc_switch_cases(ea, si)` |
| Stack var xrefs | `build_stkvar_xrefs(out, pfn, start_offset)` *(ida_frame)* |

---

## 8. Comments (All Types)
**Module:** `ida_bytes`, `ida_funcs`, `ida_segment`, `ida_lines`, `ida_idc`

| What | API Function |
|------|-------------|
| Regular comment | `get_cmt(ea, False)` *(ida_bytes)* |
| Repeatable comment | `get_cmt(ea, True)` *(ida_bytes)* |
| Function comment | `get_func_cmt(pfn, False)` *(ida_funcs)* |
| Function repeatable comment | `get_func_cmt(pfn, True)` *(ida_funcs)* |
| Segment comment | `get_segment_cmt(s, False)` *(ida_segment)* |
| Segment repeatable comment | `get_segment_cmt(s, True)` *(ida_segment)* |
| Extra anterior lines | `get_extra_cmt(ea, E_PREV)` *(ida_lines)* |
| Extra posterior lines | `get_extra_cmt(ea, E_NEXT)` *(ida_lines)* |
| Predefined insn comment | `get_predef_insn_cmt(insn)` *(ida_bytes)* |
| Has comment flag | `has_cmt(F)`, `has_extra_cmts(F)` *(ida_bytes)* |
| Bookmark comment | `get_mark_comment(slot)` *(ida_idc)* |

---

## 9. Strings
**Module:** `ida_strlist`, `ida_bytes`, `ida_nalt`

| What | API Function |
|------|-------------|
| Build string list | `build_strlist()` |
| String count | `get_strlist_qty()` |
| Get string item | `get_strlist_item(si, n)` → gives `ea`, `length`, `type` |
| String list options | `get_strlist_options()` |
| Read string contents | `get_strlit_contents(ea, len, type)` *(ida_bytes)* |
| Max string length | `get_max_strlit_length(ea, strtype)` *(ida_bytes)* |
| String type at EA | `get_str_type(ea)` *(ida_nalt)* |
| String type code | `get_str_type_code(strtype)` *(ida_nalt)* |
| Is Pascal string | `is_pascal(strtype)` *(ida_nalt)* |
| String encoding | `encoding_from_strtype(strtype)` *(ida_nalt)* |
| Print string type | `print_strlit_type(strtype)` *(ida_bytes)* |

---

## 10. Type Information
**Module:** `ida_typeinf`, `ida_nalt`

### 10a. Type Library (TIL) Management
| What | API Function |
|------|-------------|
| Get local type library | `get_idati()` |
| Load TIL | `load_til(name)` |
| Add TIL | `add_til(name, flags)` |
| TIL header | `load_til_header(tildir, name)` |

### 10b. Named Types (Structs, Enums, Typedefs, Unions)
| What | API Function |
|------|-------------|
| First named type | `first_named_type(ti, ntf_flags)` |
| Next named type | `next_named_type(ti, name, ntf_flags)` |
| Delete named type | `del_named_type(ti, name, ntf_flags)` |
| Get named type | `get_named_type(til, name, ntf_flags)` |
| Get named type64 | `get_named_type64(til, name, ntf_flags)` |
| Named type TID | `get_named_type_tid(name)` |
| TID name | `get_tid_name(tid)` |
| TID ordinal | `get_tid_ordinal(tid)` |

### 10c. Numbered (Ordinal) Types
| What | API Function |
|------|-------------|
| Ordinal limit/count | `get_ordinal_limit(ti)`, `get_ordinal_count(ti)` |
| Get numbered type | `get_numbered_type(til, ordinal)` |
| Type ordinal by name | `get_type_ordinal(ti, name)` |
| Numbered type name | `get_numbered_type_name(ti, ordinal)` |
| Is ordinal name | `is_ordinal_name(name)` |
| Alias target | `get_alias_target(ti, ordinal)` |
| Is choosable | `is_type_choosable(ti, ordinal)` |

### 10d. Type at Address
| What | API Function |
|------|-------------|
| Get type at EA | `get_tinfo(tif, ea)` *(ida_nalt)* |
| Get operand type at EA | `get_op_tinfo(tif, ea, n)` *(ida_nalt)* |
| IDC get type | `idc_get_type(ea)`, `idc_get_type_raw(ea)` |
| IDC guess type | `idc_guess_type(ea)` |
| Guess type | `guess_tinfo(out, tid)` |
| Print type at EA | `print_type(ea, flags)` |

### 10e. Local Types
| What | API Function |
|------|-------------|
| Get local type | `idc_get_local_type(ordinal, flags)` |
| Get local type raw | `idc_get_local_type_raw(ordinal)` |
| Get local type name | `idc_get_local_type_name(ordinal)` |
| Print declarations | `print_decls(printer, til, ordinals, flags)` |

### 10f. Struct/Union Members
| What | API Function |
|------|-------------|
| Iterate structs | `Structs()` *(idautils)* |
| Iterate struct members | `StructMembers(sid)` *(idautils)* |
| Find UDT member | `find_tinfo_udt_member(udm, typid, flags)` |
| Get UDM by fullname | `get_udm_by_fullname(udm, fullname)` |
| Get tinfo by EDM name | `get_tinfo_by_edm_name(tif, til, mname)` |
| Visit subtypes | `visit_subtypes(visitor, out, tif, ...)` |
| Visit stroff UDMs | `visit_stroff_udms(sfv, path, disp, ...)` |

### 10g. Enum Types
| What | API Function |
|------|-------------|
| Create enum type | `create_enum_type(name, ei, width)` |
| Get enum member expr | `get_enum_member_expr(tif, serial, value)` |

### 10h. Function Type Details
| What | API Function |
|------|-------------|
| Dump func type data | `dump_func_type_data(fti, praloc_bits)` |
| Guess func CC | `guess_func_cc(fti, npurged, cc_flags)` |
| Calc arg locations | `calc_arglocs(fti)` |
| Get arg addresses | `get_arg_addrs(caller)` |
| Stack arg area info | `get_stkarg_area_info(out, cc)` |
| Get return location | `calc_retloc(...)` |
| Func has stack hole | `func_has_stkframe_hole(ea, fti)` |
| Get idainfo by type | `get_idainfo_by_type(tif)` |
| Get tinfo by flags | `get_tinfo_by_flags(out, flags)` |

### 10i. Type Properties
| What | API Function |
|------|-------------|
| Type size | `get_tinfo_size(...)` |
| Type details | `get_tinfo_details(typid, bt2, buf)` |
| Type property | `get_tinfo_property(typid, prop)` |
| Type attributes | `get_tinfo_attrs(typid, tav, ...)` |
| Type score | `score_tinfo(tif)` |
| Type gaps | `calc_tinfo_gaps(out, typid)` |
| Type covered ranges | `append_tinfo_covered(out, typid, offset)` |
| Compare types | `compare_tinfo(t1, t2, tcflags)` |
| Print tinfo | `print_tinfo(prefix, indent, ...)`, `dstr_tinfo(tif)` |
| Serialize type | `serialize_tinfo(type, fields, fldcmts, tif, ...)` |
| Deserialize type | `deserialize_tinfo(tif, til, ptype, ...)` |
| Is type X checks | `is_type_void(t)`, `is_type_ptr(t)`, `is_type_func(t)`, `is_type_array(t)`, `is_type_typedef(t)`, `is_type_struct(t)`, `is_type_union(t)`, `is_type_enum(t)`, `is_type_bitfld(t)`, `is_type_floating(t)`, `is_type_integral(t)`, `is_type_bool(t)`, etc. |

### 10j. VFTables
| What | API Function |
|------|-------------|
| VFTable EA by ordinal | `get_vftable_ea(ordinal)` |
| VFTable ordinal by EA | `get_vftable_ordinal(vftable_ea)` |

### 10k. Compiler Info
| What | API Function |
|------|-------------|
| Compiler name/abbr | `get_compiler_name(id)`, `get_compiler_abbr(id)` |
| Get all compilers | `get_compilers(ids, names, abbrs)` |
| Default compiler | `default_compiler()` |
| Is GCC | `is_gcc()`, `is_gcc32()`, `is_gcc64()` |
| GCC layout | `gcc_layout()` |
| Stock types | `get_stock_tinfo(tif, id)` |

---

## 11. Entry Points (Exports)
**Module:** `ida_entry`, `idautils`

| What | API Function |
|------|-------------|
| Iterate entries | `Entries()` *(idautils)* |
| Entry count | `get_entry_qty()` |
| Entry ordinal | `get_entry_ordinal(idx)` |
| Entry EA | `get_entry(ord)` |
| Entry name | `get_entry_name(ord)` |
| Entry forwarder | `get_entry_forwarder(ord)` |

---

## 12. Imports
**Module:** `ida_nalt`

| What | API Function |
|------|-------------|
| Import module count | `get_import_module_qty()` |
| Import module name | `get_import_module_name(mod_index)` |
| Enumerate imports | `enum_import_names(mod_index, callback)` |

---

## 13. Stack Frames & Local Variables
**Module:** `ida_frame`

| What | API Function |
|------|-------------|
| Frame size | `get_frame_size(pfn)` |
| Frame return size | `get_frame_retsize(pfn)` |
| Frame parts | `get_frame_part(range, pfn, part)` |
| Frame offsets | `frame_off_args(pfn)`, `frame_off_retaddr(pfn)`, `frame_off_savregs(pfn)`, `frame_off_lvars(pfn)` |
| Get func frame type | `get_func_frame(out, pfn)` |
| Is func arg offset | `is_funcarg_off(pfn, frameoff)` |
| Local var offset | `lvar_off(pfn, frameoff)` |
| Stack var name | `build_stkvar_name(pfn, v)` |
| Stack delta at EA | `get_spd(pfn, ea)`, `get_effective_spd(pfn, ea)`, `get_sp_delta(pfn, ea)` |
| Register variables | `find_regvar(pfn, ea, canon)`, `has_regvar(pfn, ea)` |
| Stack var xrefs | `build_stkvar_xrefs(out, pfn, start_offset)` |
| Is special frame member | `is_special_frame_member(tid)` |
| Is anonymous/dummy member | `is_anonymous_member_name(name)`, `is_dummy_member_name(name)` |
| Calc stack offset | `calc_stkvar_struc_offset(pfn, insn, n)`, `calc_frame_offset(pfn, off)` |

---

## 14. Patches
**Module:** `ida_bytes`

| What | API Function |
|------|-------------|
| Visit all patches | `visit_patched_bytes(ea1, ea2, callable)` |
| Get original byte | `get_original_byte(ea)` |
| Get original word | `get_original_word(ea)` |
| Get original dword | `get_original_dword(ea)` |
| Get original qword | `get_original_qword(ea)` |
| Revert patch | `revert_byte(ea)` |

> **`visit_patched_bytes(ea1, ea2, callback)`** is the key function — callback receives `(ea, fpos, org_val, patch_val)` for every patched byte.

---

## 15. Hidden Ranges (Collapsed Areas)
**Module:** `ida_bytes`

| What | API Function |
|------|-------------|
| Get hidden range at EA | `get_hidden_range(ea)` |
| Get by index | `getn_hidden_range(n)` |
| Count | `get_hidden_range_qty()` |
| Get range number | `get_hidden_range_num(ea)` |
| Navigate | `get_first_hidden_range()`, `get_last_hidden_range()`, `get_prev_hidden_range(ea)`, `get_next_hidden_range(ea)` |

---

## 16. Bookmarks / Marked Positions
**Module:** `ida_idc`

| What | API Function |
|------|-------------|
| Get marked position EA | `get_marked_pos(slot)` *(slot 1-1024)* |
| Get bookmark comment | `get_mark_comment(slot)` |

> Iterate slots 1–1024, check for `BADADDR` to find all bookmarks.

---

## 17. Switch/Jump Tables
**Module:** `ida_nalt`, `ida_xref`

| What | API Function |
|------|-------------|
| Get switch info | `get_switch_info(out, ea)` *(ida_nalt)* |
| Get switch parent | `get_switch_parent(ea)` *(ida_nalt)* |
| Calc switch cases | `calc_switch_cases(ea, si)` *(ida_xref)* |
| Create switch xrefs | `create_switch_xrefs(ea, si)` *(ida_xref)* |

> `switch_info_t` contains: `jumps`, `ncases`, `startea`, `defjump`, `lowcase`, `elbase`, etc.

---

## 18. Fixups / Relocations
**Module:** `ida_fixup`

| What | API Function |
|------|-------------|
| Get fixup at EA | `get_fixup(fd, source)` |
| Fixup exists | `exists_fixup(source)` |
| Enumerate fixups | `get_first_fixup_ea()`, `get_next_fixup_ea(ea)`, `get_prev_fixup_ea(ea)` |
| Fixup description | `get_fixup_desc(source, fd)` |
| Fixup value | `get_fixup_value(ea, type)` |
| Fixup handler | `get_fixup_handler(type)` |
| Fixup size | `calc_fixup_size(type)` |
| Contains fixups | `contains_fixups(ea, size)` |
| Get fixups in range | `get_fixups(out, ea, size)` |
| Is custom fixup | `is_fixup_custom(type)` |

---

## 19. Try/Catch Exception Handlers
**Module:** `ida_tryblks`

| What | API Function |
|------|-------------|
| Get try blocks in range | `get_tryblks(tbv, range)` |
| Find SEH handler | `find_syseh(ea)` |
| Is EA in try blocks | `is_ea_tryblks(ea, flags)` |

> `tryblk_t` contains: try range, catch/handler ranges, catch types.

---

## 20. Problems / Analysis Issues
**Module:** `ida_problems`

| What | API Function |
|------|-------------|
| Get problem at type/EA | `get_problem(type, lowea)` → returns (EA, desc) |
| Problem description | `get_problem_desc(t, ea)` |
| Problem name | `get_problem_name(type)` |
| Is problem present | `is_problem_present(t, ea)` |
| Was IDA's decision | `was_ida_decision(ea)` |

> Problem types: `PR_NOBASE`, `PR_NONAME`, `PR_NOFOP`, `PR_NOCMT`, `PR_NOXREFS`, `PR_JUMP`, `PR_DISASM`, `PR_HEAD`, `PR_ILLADDR`, `PR_ATTN`, `PR_FINAL`, `PR_ROLLED`, `PR_COLLISION`

---

## 21. Segment Registers
**Module:** `ida_segregs`

| What | API Function |
|------|-------------|
| Get sreg value at EA | `get_sreg(ea, rg)` |
| Get sreg range at EA | `get_sreg_range(out, ea, rg)` |
| Get previous sreg range | `get_prev_sreg_range(out, ea, rg)` |
| Sreg ranges count | `get_sreg_ranges_qty(rg)` |
| Get sreg range by index | `getn_sreg_range(out, rg, n)` |
| Get sreg range number | `get_sreg_range_num(ea, rg)` |

---

## 22. Operand Representation
**Module:** `ida_bytes`

| What | API Function |
|------|-------------|
| Operand type flags | `get_optype_flags0(F)`, `get_optype_flags1(F)` |
| Is offset/char/seg/enum/stroff/stkvar/float/custfmt/numeric | `is_off(F,n)`, `is_char(F,n)`, `is_seg(F,n)`, `is_enum(F,n)`, `is_stroff(F,n)`, `is_stkvar(F,n)`, `is_fltnum(F,n)`, `is_custfmt(F,n)`, `is_numop(F,n)` |
| Is defined operand | `is_defarg(F, n)`, `is_defarg0(F)`, `is_defarg1(F)` |
| Sign/negate/leading zero | `is_invsign(ea, F, n)`, `is_bnot(ea, F, n)`, `is_lzero(ea, n)` |
| Enum applied to operand | `get_enum_id(ea, n)` |
| Operand adds xrefs | `op_adds_xrefs(F, n)` |

---

## 23. Reference Info (Offsets)
**Module:** `ida_nalt`, `ida_offset`

| What | API Function |
|------|-------------|
| Get refinfo at operand | `get_refinfo(ri, ea, n)` *(ida_nalt)* |
| Set refinfo | `set_refinfo(...)` *(ida_nalt)* |
| Offset base | `get_offbase(ea, n)` *(ida_offset)* |
| Offset expression | `get_offset_expression(ea, n, from, ...)` *(ida_offset)* |
| Default ref type | `get_default_reftype(ea)` *(ida_offset)* |
| Calc reference data | `calc_reference_data(target, base, from, ...)` *(ida_offset)* |
| Calc offset base | `calc_offset_base(ea, n)` *(ida_offset)* |
| Calc target | `calc_target(...)` *(ida_offset)* |

---

## 24. FLIRT / Library Signatures
**Module:** `ida_funcs`, `ida_libfuncs`

| What | API Function |
|------|-------------|
| Signature count | `get_idasgn_qty()` *(ida_funcs)* |
| Current signature | `get_current_idasgn()` *(ida_funcs)* |
| Signature state | `calc_idasgn_state(n)` *(ida_funcs)* |
| Signature title | `get_idasgn_title(name)` *(ida_funcs)* |
| Signature description | `get_idasgn_desc(n)`, `get_idasgn_desc_with_matches(n)` *(ida_funcs)* |
| Signature header | `get_idasgn_header_by_short_name(out, name)` *(ida_libfuncs)* |
| Signature path | `get_idasgn_path_by_short_name(name)` *(ida_libfuncs)* |

---

## 25. Additional Flags (aflags — Per-Address Metadata)
**Module:** `ida_nalt`

| What | API Function |
|------|-------------|
| Get all aflags | `get_aflags(ea)` |
| Source line number | `get_source_linnum(ea)` |
| Absolute base | `get_absbase(ea)` |
| Indirect purged | `get_ind_purged(ea)` |
| Alignment | `get_alignment(ea)` |
| Item color | `get_item_color(ea)` |
| Array parameters | `get_array_parameters(out, ea)` |
| Custom data type IDs | `get_custom_data_type_ids(cdis, ea)` |
| Is hidden item/border | `is_hidden_item(ea)`, `is_hidden_border(ea)` |
| Is library item | `is_libitem(ea)` |
| Is no-return | `is_noret(ea)` |
| Is colored | `is_colored_item(ea)` |
| Is visible | `is_visible_item(ea)`, `is_finally_visible_item(ea)` |
| Type guess origin | `is_type_guessed_by_ida(ea)`, `is_func_guessed_by_hexrays(ea)`, `is_data_guessed_by_hexrays(ea)`, `is_type_determined_by_hexrays(ea)` |
| Fixed SP delta | `is_fixed_spd(ea)` |
| Uses modsp | `uses_modsp(ea)` |
| Terse struct display | `is_terse_struc(ea)` |
| Is not-code | `is_notcode(ea)` |
| Is not-proc | `is_notproc(ea)` |
| Has type info | `has_ti(ea)`, `has_ti0(ea)`, `has_ti1(ea)` |
| Has long name | `has_lname(ea)` |
| User-set SP | `is_usersp(ea)` |
| Return FP | `is_retfp(ea)` |

---

## 26. Auto-Analysis State
**Module:** `ida_auto`

| What | API Function |
|------|-------------|
| Analysis state | `get_auto_state()` |
| Auto display info | `get_auto_display(auto_display)` |
| Auto-analysis enabled | `is_auto_enabled()` |
| Analysis complete | `auto_is_ok()` |
| Peek auto queue | `peek_auto_queue(low_ea, type)` |

---

## 27. Debugger Info (Stored in IDB)
**Module:** `ida_dbg`

### 27a. Breakpoints
| What | API Function |
|------|-------------|
| Breakpoint count | `get_bpt_qty()` |
| Get breakpoint by index | `getn_bpt(n, bpt)` |
| Get breakpoint at EA | `get_bpt(ea, bpt)` |
| Find breakpoint | `find_bpt(bptloc, bpt)` |
| Breakpoint exists | `exist_bpt(ea)` |
| Breakpoint group | `get_bpt_group(bptloc)` |
| List all BP groups | `list_bptgrps()` |
| Group breakpoints | `get_grp_bpts(bpts, grp_name)` |
| BP location string | `get_bptloc_string(i)` |

### 27b. Trace Events
| What | API Function |
|------|-------------|
| Trace event count | `get_tev_qty()` |
| Get trace event info | `get_tev_info(n, tev_info)` |
| Trace event EA | `get_tev_ea(n)` |
| Trace event type | `get_tev_type(n)` |
| Trace event TID | `get_tev_tid(n)` |
| Insn trace reg value | `get_insn_tev_reg_val(n, regname, regval)` |
| Insn trace reg result | `get_insn_tev_reg_result(n, regname, regval)` |
| Insn trace memory | `get_insn_tev_reg_mem(n, memmap)` |
| Call trace callee | `get_call_tev_callee(n)` |
| Return trace return | `get_ret_tev_return(n)` |
| BP trace EA | `get_bpt_tev_ea(n)` |
| Trace event memory | `get_tev_memory_info(n, mi)` |
| Trace event debug event | `get_tev_event(n, d)` |
| Trace base address | `get_trace_base_address()` |
| Trace platform | `get_trace_platform()` |

### 27c. Debug State
| What | API Function |
|------|-------------|
| Process state | `get_process_state()` |
| Is debugger on | `is_debugger_on()` |
| Thread count | `get_thread_qty()` |
| Get thread | `getn_thread(n)` |
| Current thread | `get_current_thread()` |
| Thread name | `getn_thread_name(n)` |
| Module info | `get_first_module(modinfo)`, `get_next_module(modinfo)`, `get_module_info(ea, modinfo)` |
| Modules list | `Modules()` *(idautils)* |
| Memory info | `get_dbg_memory_info(ranges)` |
| Stack trace | `collect_stack_trace(tid, trace)` |
| Process options | `get_process_options(...)`, `get_process_options2(...)` |
| Debug register info | `get_dbg_reg_info(regname, ri)` |
| Register value | `get_reg_val(regname)`, `get_reg_vals(tid, clsmask)` |
| SP/IP values | `get_sp_val()`, `get_ip_val()` |
| Manual regions | `get_manual_regions(...)` |
| Debugger event cond | `get_debugger_event_cond()` |
| Exceptions | `retrieve_exceptions()` |
| Source debug info | `get_local_vars(prov, ea, out)`, `get_global_var(prov, ea, name, ...)`, `get_local_var(prov, ea, name, ...)` |
| Source file | `get_current_source_file()`, `get_current_source_line()` |
| Is debugger memory | `is_debugger_memory(ea)` |
| Read debug memory | `read_dbg_memory(ea, buffer, size)`, `get_dbg_byte(ea)` |

### 27d. Trace Files
| What | API Function |
|------|-------------|
| Load trace file | `load_trace_file(filename)` |
| Is valid trace file | `is_valid_trace_file(filename)` |
| Trace file desc | `get_trace_file_desc(filename)` |
| Trace options | `get_step_trace_options()`, `get_insn_trace_options()`, `get_func_trace_options()`, `get_bblk_trace_options()` |

---

## 28. Custom Data Types & Formats
**Module:** `ida_bytes`

| What | API Function |
|------|-------------|
| Get custom data type | `get_custom_data_type(dtid)` |
| Get custom data format | `get_custom_data_format(dfid)` |
| List all custom types | `get_custom_data_types(...)` |
| List all custom formats | `get_custom_data_formats(out, dtid)` |
| Find custom type by name | `find_custom_data_type(name)` |
| Find custom format by name | `find_custom_data_format(name)` |
| Is attached format | `is_attached_custom_data_format(dtid, dfid)` |

---

## 29. Control Flow Graphs
**Module:** `ida_gdl`

| What | API Function |
|------|-------------|
| Generate flow graph | `gen_flow_graph(filename, title, pfn, ...)` |
| Generate simple call chart | `gen_simple_call_chart(filename, ...)` |
| Generate complex call chart | `gen_complex_call_chart(filename, ...)` |
| Is no-ret / return block | `is_noret_block(btype)`, `is_ret_block(btype)` |

---

## 30. Hex-Rays Decompiler Data
**Module:** `ida_hexrays`

| What | API Function |
|------|-------------|
| Decompile function | `decompile(ea)`, `decompile_func(pfn)`, `decompile_many(outfile, ...)` |
| Hex-Rays version | `get_hexrays_version()` |
| Init Hex-Rays | `init_hexrays_plugin()` |
| User labels | `restore_user_labels(func_ea)`, `save_user_labels(...)` |
| User comments | `restore_user_cmts(func_ea)`, `save_user_cmts(...)` |
| User number formats | `restore_user_numforms(func_ea)`, `save_user_numforms(...)` |
| User item flags | `restore_user_iflags(func_ea)`, `save_user_iflags(...)` |
| User unions | `restore_user_unions(func_ea)`, `save_user_unions(...)` |
| User lvar settings | `restore_user_lvar_settings(lvinf, func_ea)` |
| User-defined calls | `restore_user_defined_calls(udcalls, func_ea)` |
| Is dirty | `mark_cfunc_dirty(ea)` |
| Pseudocode view | `open_pseudocode(ea, flags)` |

---

## 31. Color / Visual Info
**Module:** `ida_nalt`, `ida_lines`

| What | API Function |
|------|-------------|
| Item color | `get_item_color(ea)` *(ida_nalt)* |
| Is colored item | `is_colored_item(ea)` *(ida_nalt)* |
| Prefix color | `calc_prefix_color(ea)` *(ida_lines)* |
| Background color | `calc_bg_color(ea)` *(ida_lines)* |

---

## 32. Source File Mapping
**Module:** `ida_lines`, `ida_nalt`

| What | API Function |
|------|-------------|
| Get source file | `get_sourcefile(ea)` *(ida_lines)* |
| Source line number | `get_source_linnum(ea)` *(ida_nalt)* |
| Source debug paths | `get_srcdbg_paths()` *(ida_nalt)* |

---

## 33. Processor-Specific Info
**Module:** `ida_idp`

| What | API Function |
|------|-------------|
| Processor handle | `get_ph()` |
| Assembler handle | `get_ash()` |
| IDP name | `get_idp_name()` |
| Processor ID | `ph_get_id()` |
| Processor version | `ph_get_version()` |
| Processor flags | `ph_get_flag()` |
| Code/data bits | `ph_get_cnbits()`, `ph_get_dnbits()` |
| Register names | `ph_get_regnames()`, `get_reg_name(reg, width)` |
| Register list | `GetRegisterList()` *(idautils)* |
| Instruction set | `GetInstructionList()` *(idautils)*, `ph_get_instruc()` |
| Segreg info | `ph_get_reg_first_sreg()`, `ph_get_reg_last_sreg()`, `ph_get_segreg_size()`, `ph_get_reg_code_sreg()`, `ph_get_reg_data_sreg()` |
| Tbyte size | `ph_get_tbyte_size()` |
| Operand info | `ph_get_operand_info(ea, n)` |
| Register accesses | `ph_get_reg_accesses(accvec, insn, flags)` |
| ABI info | `ph_get_abi_info(comp)` |
| CC header path | `cfg_get_cc_header_path(compid)` |
| CC predefined macros | `cfg_get_cc_predefined_macros(compid)` |
| Config value | `get_config_value(key)` |
| Delay slot insn | `delay_slot_insn(ea, bexec, fexec)` |

---

## 34. Calling Conventions & Compiler Info
**Module:** `ida_typeinf`

| What | API Function |
|------|-------------|
| Is user CC | `is_user_cc(cc)` |
| Is vararg CC | `is_vararg_cc(cc)` |
| Is purging CC | `is_purging_cc(cc)` |
| Is golang CC | `is_golang_cc(cc)` |
| Is swift CC | `is_swift_cc(cc)` |
| Is custom CC | `is_custom_callcnv(cc)` |
| Get custom CC | `get_custom_callcnv(callcnv)` |
| Find custom CC | `find_custom_callcnv(name)` |
| All custom CCs | `get_custom_callcnvs(names, codes)` |
| Stack arg area | `get_stkarg_area_info(out, cc)` |
| Compiler name/abbr | `get_compiler_name(id)`, `get_compiler_abbr(id)` |
| All compilers | `get_compilers(ids, names, abbrs)` |

---

## 35. Register Value Tracking
**Module:** `ida_regfinder`

| What | API Function |
|------|-------------|
| Find reg value at EA | `find_reg_value(ea, reg)` |
| Find SP value at EA | `find_sp_value(ea, reg)` |
| Find reg value info | `find_reg_value_info(rvi, ea, reg)` |
| Find nearest RVI | `find_nearest_rvi(rvi, ea, reg)` |

Also in `ida_idp`:
| What | API Function |
|------|-------------|
| Find reg value (IDP) | `ph_find_reg_value(insn, reg)` |
| Find operand value | `ph_find_op_value(insn, op)` |

---

## 36. Address Mappings
**Module:** `ida_bytes`

| What | API Function |
|------|-------------|
| Get mapping count | `get_mappings_qty()` |
| Get mapping at index | `get_mapping(n)` → returns (from, to, size) |
| Use mapping | `use_mapping(ea)` |

---

## 37. File Regions
**Module:** `ida_loader`

| What | API Function |
|------|-------------|
| File offset from EA | `get_fileregion_offset(ea)` |
| EA from file offset | `get_fileregion_ea(offset)` |

---

## 38. Extra Lines (Anterior/Posterior)
**Module:** `ida_lines`

| What | API Function |
|------|-------------|
| Get extra comment | `get_extra_cmt(ea, what)` — `E_PREV` (anterior), `E_NEXT` (posterior) |
| First free extra index | `get_first_free_extra_cmtidx(ea, start)` |

---

## 39. Encodings
**Module:** `ida_nalt`

| What | API Function |
|------|-------------|
| Encoding count | `get_encoding_qty()` |
| Encoding name | `get_encoding_name(idx)` |
| Encoding BPU | `get_encoding_bpu(idx)`, `get_encoding_bpu_by_name(encname)` |
| Default encoding | `get_default_encoding_idx(bpu)` |
| String type BPU | `get_strtype_bpu(strtype)` |
| Output file encoding | `get_outfile_encoding_idx()` |
| Encoding from strtype | `encoding_from_strtype(strtype)` |

---

## 40. Search Functions
**Module:** `ida_search`

| What | API Function |
|------|-------------|
| Find error | `find_error(ea, sflag)` |
| Find no-type | `find_notype(ea, sflag)` |
| Find unknown bytes | `find_unknown(ea, sflag)` |
| Find defined bytes | `find_defined(ea, sflag)` |
| Find suspicious operand | `find_suspop(ea, sflag)` |
| Find data | `find_data(ea, sflag)` |
| Find code | `find_code(ea, sflag)` |
| Find not function | `find_not_func(ea, sflag)` |
| Find immediate value | `find_imm(ea, sflag, search_value)` |
| Find text | `find_text(start_ea, y, x, ustr, sflag)` |
| Find register access | `find_reg_access(out, start_ea, end_ea, ...)` |

---

## 41. Utility Iterators (idautils)
**Module:** `idautils`

| What | API Function |
|------|-------------|
| All heads (code+data) | `Heads(start, end)` |
| All functions | `Functions(start, end)` |
| Function items | `FuncItems(start)` |
| Function chunks | `Chunks(start)` |
| All segments | `Segments()` |
| All names | `Names()` |
| All entries | `Entries()` |
| All structs | `Structs()` |
| Struct members | `StructMembers(sid)` |
| All threads | `Threads()` |
| All modules | `Modules()` |
| Code refs to/from | `CodeRefsTo(ea, flow)`, `CodeRefsFrom(ea, flow)` |
| Data refs to/from | `DataRefsTo(ea)`, `DataRefsFrom(ea)` |
| All xrefs to/from | `XrefsTo(ea, flags)`, `XrefsFrom(ea, flags)` |
| Data list | `GetDataList(ea, count, itemsize)` |
| Register list | `GetRegisterList()` |
| Instruction list | `GetInstructionList()` |
| Decode instruction | `DecodeInstruction(ea)` |

---

## 42. Low-Level Database (Netnodes)
**Module:** `ida_netnode`

| What | API Function |
|------|-------------|
| Node exists | `exist(n)` |

> The `netnode` class has extensive methods: `supval()`, `supstr()`, `hashval()`, `altval()`, etc. for low-level blob/tag storage. Use `ida_nalt.getnode(ea)` to get a netnode for any address.

---

## 43. Directory Trees (Dirtree)
**Module:** `ida_dirtree`

| What | API Function |
|------|-------------|
| Get standard dirtree | `get_std_dirtree(id)` |

> Dirtree IDs: `DIRTREE_FUNCS`, `DIRTREE_NAMES`, `DIRTREE_IMPORTS`, `DIRTREE_ENUMS`, `DIRTREE_STRUCTS`, `DIRTREE_BPTS`, `DIRTREE_LOCAL_TYPES`, etc. Each dirtree has a `find()`, `get_entry()`, `get_entry_name()` interface for organized browsing.

---

## 44. Selectors
**Module:** `ida_segment`

| What | API Function |
|------|-------------|
| Selector count | `get_selector_qty()` |
| Get selector by index | `getn_selector(n)` → returns (sel, ea) |
| Selector to paragraph | `sel2para(selector)` |
| Selector to EA | `sel2ea(selector)` |
| Find selector | `find_selector(base)` |

---

## Summary: Complete Dumpable Data Categories

| # | Category | Key Module(s) | ~Functions |
|---|----------|---------------|-----------|
| 1 | Database metadata | ida_ida, ida_nalt, ida_loader | ~80 |
| 2 | Segments | ida_segment | ~30 |
| 3 | Functions | ida_funcs | ~35 |
| 4 | Instructions/disasm | ida_ua, ida_lines | ~20 |
| 5 | Bytes/data/memory | ida_bytes | ~60 |
| 6 | Names/labels | ida_name | ~30 |
| 7 | Cross-references | ida_xref | ~20 |
| 8 | Comments (all types) | ida_bytes, ida_funcs, ida_segment, ida_lines | ~12 |
| 9 | Strings | ida_strlist, ida_nalt | ~12 |
| 10 | Type info (structs/enums/unions/typedefs/func types) | ida_typeinf | ~80+ |
| 11 | Entry points | ida_entry | ~6 |
| 12 | Imports | ida_nalt | ~3 |
| 13 | Stack frames/locals | ida_frame | ~25 |
| 14 | Patches | ida_bytes | ~5 |
| 15 | Hidden ranges | ida_bytes | ~8 |
| 16 | Bookmarks | ida_idc | ~2 |
| 17 | Switch tables | ida_nalt, ida_xref | ~4 |
| 18 | Fixups/relocations | ida_fixup | ~12 |
| 19 | Try/catch handlers | ida_tryblks | ~3 |
| 20 | Problems/issues | ida_problems | ~5 |
| 21 | Segment registers | ida_segregs | ~7 |
| 22 | Operand representation | ida_bytes | ~15 |
| 23 | Reference/offset info | ida_nalt, ida_offset | ~10 |
| 24 | FLIRT signatures | ida_funcs, ida_libfuncs | ~8 |
| 25 | Additional flags (aflags) | ida_nalt | ~30 |
| 26 | Auto-analysis state | ida_auto | ~5 |
| 27 | Debugger data | ida_dbg | ~60 |
| 28 | Custom data types | ida_bytes | ~7 |
| 29 | Control flow graphs | ida_gdl | ~5 |
| 30 | Hex-Rays decompiler | ida_hexrays | ~15 |
| 31 | Color/visual | ida_nalt, ida_lines | ~4 |
| 32 | Source file mapping | ida_lines, ida_nalt | ~3 |
| 33 | Processor info | ida_idp | ~25 |
| 34 | Calling conventions | ida_typeinf | ~12 |
| 35 | Register tracking | ida_regfinder | ~4 |
| 36 | Address mappings | ida_bytes | ~3 |
| 37 | File regions | ida_loader | ~2 |
| 38 | Extra lines | ida_lines | ~2 |
| 39 | Encodings | ida_nalt | ~8 |
| 40 | Search functions | ida_search | ~10 |
| 41 | Utility iterators | idautils | ~20 |
| 42 | Netnodes (low-level) | ida_netnode | ~1+ class |
| 43 | Directory trees | ida_dirtree | ~1+ class |
| 44 | Selectors | ida_segment | ~5 |

**Total: ~750+ data-extraction API functions across 44 categories**

---

*Generated from IDA Pro 9.2 Python SDK analysis — February 2026*
