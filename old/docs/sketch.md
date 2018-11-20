# SOURCE FILES

## tools/bootstrap.cpp : Binary *B* -> LLVM Module *M*
### Description
1. creates a bare-bones skeleton LLVM module for a given binary
2. takes relocations, imported & exported symbols into account
3. does an initial recursive descent and static control flow recovery

## lib/core/translate.cpp : LLVM Module *M*, binary *B*, virtual address *A* -> LLVM Module *M'*
### Description
1. produces LLVM code from machine code utilizing libqemutcg
2. takes relocations into account

### Pre-Conditions
1. M must contain a sorted table `_j_trans_table` of (virtual address, LLVM function) pairs

## lib/dynamic/instrumentation.cpp
### Description
1. code that runs in decompiled binary if necessary
2. provides an exported function `_j_trans_code` which given a virtual address, returns a function pointer to translated code corresponding to that address
3. if there does not exist LLVM code for the given virtual address, it does the translation utilizing libqemutcg
4. new translated code is stored in LLVM module corresponding to decompiled binary
5. LLVM module for a given binary is stored in a shadow filesystem located in a root directory of the user's choosing
6. new translated code is JIT-compiled

# DYNAMIC CONTROL FLOW RECOVERY
Given a binary *B*, we proceed as follows:
1. For every library *L* opened by binary *B*, we overwrite its place in the filesystem with the compiled output *L'* of **bootstrap**.
2. *L'* shall contain a structurally identical relocation and symbol table to
*L*.
  1. TLS
  2. PLT
  3. GOT
3. An indirect jump to the address *A* shall be translated to implement the following procedure:
  1. Determine whether *A* falls within memory having executable permissions
    1. On Linux platforms: `dl_iterate_phdr`
      * Examine ELF program headers using `dlpi_phdr`, find which segment *A* falls under and check `Elf_Phdr::p_flags` for `PF_X`
    2. On Windows platforms: `EnumProcessModulesEx`, `VirtualProtect` (examine `lpflOldProtect`, afterwards revert using `flNewProtect`)
      * Alternatively, determine which section *A* falls under, and examine that COFF section's attributes
  2. If so, then cast *A* to function pointer to translated code (LLVM) and call it.
  3. Otherwise, we call `_j_trans_code` exported from the relevant binary
    1. Find `_j_trans_code` from looking for a special section with the name `_j_trans_code_sect`
