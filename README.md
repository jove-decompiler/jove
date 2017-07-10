# Jove: A Dynamic Decompiler

![Alt text](/docs/overview.png?raw=true)
# Examples
## complex-num
### Source Code
```c
#include <stdio.h>
#include <stdlib.h>

#define COMPLEX_PART_FMT "%li"
typedef long int complex_part_t;

struct complex_t {
  complex_part_t real;
  complex_part_t imag;
};

__attribute__ ((noinline)) struct complex_t cn_add(struct complex_t a, struct complex_t b);
__attribute__ ((noinline)) struct complex_t cn_sub(struct complex_t a, struct complex_t b);
__attribute__ ((noinline)) struct complex_t cn_mul(struct complex_t a, struct complex_t b);
__attribute__ ((noinline)) struct complex_t cn_div(struct complex_t a, struct complex_t b);

int main(int argc, char **argv) {
  if (argc != 6) {
    printf("usage: complex-num w x [+-*/] y z\n");
    return 0;
  }

  struct complex_t a, b;
  a.real = atol(argv[1]);
  a.imag = atol(argv[2]);
  b.real = atol(argv[4]);
  b.imag = atol(argv[5]);

  struct complex_t c;
  switch (argv[3][0]) {
  case '+':
    c = cn_add(a, b);
    break;
  case '-':
    c = cn_sub(a, b);
    break;
  case '*':
    c = cn_mul(a, b);
    break;
  case '/':
    c = cn_div(a, b);
    break;
  default:
    return 1;
  };

  printf(COMPLEX_PART_FMT " + " COMPLEX_PART_FMT "i\n", c.real, c.imag);
  return 0;
}

struct complex_t cn_add(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  c.real = a.real + b.real;
  c.imag = a.imag + b.imag;
  return c;
}
struct complex_t cn_sub(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  c.real = a.real - b.real;
  c.imag = a.imag - b.imag;
  return c;
}
struct complex_t cn_mul(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  c.real = a.real * b.real - a.imag * b.imag;
  c.imag = a.imag * b.real + a.real * b.imag;
  return c;
}
struct complex_t cn_div(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  complex_part_t denom = b.real * b.real + b.imag * b.imag;
  c.real = (a.real * b.real + a.imag * b.imag) / denom;
  c.imag = (a.imag * b.real - a.real * b.imag) / denom;
  return c;
}
```
### AAarch64
#### Machine Code
```asm
000000000000093c <cn_add>:
 93c:   d100c3ff        sub     sp, sp, #0x30
 940:   a90107e0        stp     x0, x1, [sp, #16]
 944:   a9000fe2        stp     x2, x3, [sp]
 948:   3dc007e0        ldr     q0, [sp, #16]
 94c:   3dc003e1        ldr     q1, [sp]
 950:   4ee18400        add     v0.2d, v0.2d, v1.2d
 954:   3d800be0        str     q0, [sp, #32]
 958:   a94207e0        ldp     x0, x1, [sp, #32]
 95c:   9100c3ff        add     sp, sp, #0x30
 960:   d65f03c0        ret

0000000000000964 <cn_sub>:
 964:   d100c3ff        sub     sp, sp, #0x30
 968:   a90107e0        stp     x0, x1, [sp, #16]
 96c:   a9000fe2        stp     x2, x3, [sp]
 970:   3dc007e0        ldr     q0, [sp, #16]
 974:   3dc003e1        ldr     q1, [sp]
 978:   6ee18400        sub     v0.2d, v0.2d, v1.2d
 97c:   3d800be0        str     q0, [sp, #32]
 980:   a94207e0        ldp     x0, x1, [sp, #32]
 984:   9100c3ff        add     sp, sp, #0x30
 988:   d65f03c0        ret

000000000000098c <cn_mul>:
 98c:   9b007c46        mul     x6, x2, x0
 990:   aa0103e5        mov     x5, x1
 994:   9b007c61        mul     x1, x3, x0
 998:   9b050441        madd    x1, x2, x5, x1
 99c:   9b059860        msub    x0, x3, x5, x6
 9a0:   d65f03c0        ret

00000000000009a4 <cn_div>:
 9a4:   9b017c46        mul     x6, x2, x1
 9a8:   9b017c65        mul     x5, x3, x1
 9ac:   9b037c64        mul     x4, x3, x3
 9b0:   9b021041        madd    x1, x2, x2, x4
 9b4:   9b009863        msub    x3, x3, x0, x6
 9b8:   9b001442        madd    x2, x2, x0, x5
 9bc:   9ac10c40        sdiv    x0, x2, x1
 9c0:   9ac10c61        sdiv    x1, x3, x1
 9c4:   d65f03c0        ret
```
#### Running Jove
```bash
$ # $PWD is $JOVE_SRC_DIR/bin/aarch64
$ ./jove-init ../../tests/bin/gcc/debian-jessie/aarch64/complex-num
File: ../../tests/bin/gcc/debian-jessie/aarch64/complex-num
Format: ELF64-aarch64-little
Arch: aarch64
AddressSize: 64bit
MC TheTriple: aarch64-unknown-unknown-elf
MC TheTarget: AArch64 (little endian)

Address Space:
.interp              [200, 21b)
.note.ABI-tag        [21c, 23c)
.note.gnu.build-id   [23c, 260)
.dynsym              [260, 368)
.dynstr              [368, 411)
.gnu.hash            [418, 434)
.gnu.version         [434, 44a)
.gnu.version_r       [44c, 46c)
.rela.dyn            [470, 578)
.rela.plt            [578, 620)
.init                [620, 634)
.plt                 [638, 6c8)
.text                [6c8, a44)
.fini                [a44, a54)
.rodata              [a58, a9c)
.eh_frame            [a9c, aa0)
.eh_frame_hdr        [aa0, aa8)
.dynamic             [1aa8, 1c88)
.got                 [1c88, 1cd0)
.got.plt             [1cd0, 1d20)
.data                [1d20, 1d30)
.jcr                 [1d30, 1d38)
.fini_array          [1d38, 1d40)
.init_array          [1d40, 1d48)
.bss                 [1d48, 1d49)

Relocations:

  RELATIVE     @ 1c90             +6c8             
  RELATIVE     @ 1c98             +9c8             
  RELATIVE     @ 1ca0             +a40             
  RELATIVE     @ 1d28             +1d28            
  RELATIVE     @ 1d38             +8c0             
  RELATIVE     @ 1d40             +908             
  ADDRESSOF    @ 1cc0             +0               __cxa_finalize                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1ca8             +0               __gmon_start__                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1cb0             +0               _ITM_deregisterTMCloneTable    *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1cb8             +0               _ITM_registerTMCloneTable      *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1cc8             +0               _Jv_RegisterClasses            *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1ce8             +0               __libc_start_main              *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1cf0             +0               abort                          *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1cf8             +0               __gmon_start__                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1d00             +0               __cxa_finalize                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1d08             +0               puts                           *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1d10             +0               strtol                         *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1d18             +0               printf                         *FUNCTION   *GLOBAL   @ 0 {0}

Translating aarch64 machine code to QEMU IR...

9a4
  9a4
    note: return
93c
  93c
    note: return
a44
  a44
    note: return
6c8
  6c8
    note: conditional jump to 6e4 and 704
  6e4
    note: direct call to 698
  6f0
    note: return
  704
    note: direct call to 6a8
  714
    note: direct call to 6a8
  728
    note: direct call to 6a8
  73c
    note: direct call to 6a8
  750
    note: conditional jump to 764 and 76c
  764
    note: unconditional jump to 6f4
  6f4
    note: return
  76c
    note: indirect jump
9c8
  9c8
    note: direct call to 620
  a08
    note: conditional jump to a0c and a2c
  a0c
    note: indirect call
  a20
    note: conditional jump to a2c and a0c
  a2c
    note: return
808
  808
    note: direct call to 658
  83c
    note: direct call to 668
  840
    note: conditional jump to 84c and 850
  84c
    note: unconditional jump to 678
  678
    note: indirect jump
  850
    note: return
964
  964
    note: return
854
  854
    note: conditional jump to 874 and 884
  874
    note: conditional jump to 880 and 884
  880
    note: indirect jump
  884
    note: return
620
  620
    note: direct call to 840
  62c
    note: return
840
  840
    note: conditional jump to 84c and 850
  84c
    note: unconditional jump to 678
  678
    note: indirect jump
  850
    note: return
888
  888
    note: conditional jump to 8ac and 8bc
  8ac
    note: conditional jump to 8b8 and 8bc
  8b8
    note: indirect jump
  8bc
    note: return
98c
  98c
    note: return
8c0
  8c0
    note: conditional jump to 8d8 and 8fc
  8d8
    note: conditional jump to 8e4 and 8f0
  8e4
    note: direct call to 688
  8f0
    note: direct call to 854
  8f4
    note: return
  8fc
    note: return
908
  908
    note: conditional jump to 920 and 928
  920
    note: unconditional jump to 888
  888
    note: conditional jump to 8ac and 8bc
  8ac
    note: conditional jump to 8b8 and 8bc
  8b8
    note: indirect jump
  8bc
    note: return
  928
    note: conditional jump to 934 and 920
  934
    note: indirect call
  938
    note: unconditional jump to 920
a40
  a40
    note: return
698
  698
    note: indirect jump
6a8
  6a8
    note: indirect jump
658
  658
    note: indirect jump
668
  668
    note: indirect jump
688
  688
    note: indirect jump

Translating QEMU IR to LLVM...

688
  688
    note: PC-relative expression @ 688
668
  668
    note: PC-relative expression @ 668
9a4
  9a4
808
  808
    note: PC-relative expression @ 820
    note: PC-relative expression @ 828
    note: PC-relative expression @ 830
  83c
  840
    note: PC-relative expression @ 840
  84c
  678
    note: PC-relative expression @ 678
  850
9c8
  9c8
    note: PC-relative expression @ 9d8
    note: PC-relative expression @ 9dc
  a08
  a0c
  a20
  a2c
658
  658
    note: PC-relative expression @ 658
93c
  93c
964
  964
698
  698
    note: PC-relative expression @ 698
854
  854
    note: PC-relative expression @ 854
    note: PC-relative expression @ 858
  874
    note: PC-relative expression @ 874
  880
  884
620
  620
  62c
840
  840
    note: PC-relative expression @ 840
  84c
  678
    note: PC-relative expression @ 678
  850
a44
  a44
888
  888
    note: PC-relative expression @ 888
    note: PC-relative expression @ 88c
  8ac
    note: PC-relative expression @ 8ac
  8b8
  8bc
6a8
  6a8
    note: PC-relative expression @ 6a8
98c
  98c
8c0
  8c0
    note: PC-relative expression @ 8cc
  8d8
    note: PC-relative expression @ 8d8
  8e4
    note: PC-relative expression @ 8e4
  8f0
  8f4
  8fc
908
  908
    note: PC-relative expression @ 90c
  920
  888
    note: PC-relative expression @ 888
    note: PC-relative expression @ 88c
  8ac
    note: PC-relative expression @ 8ac
  8b8
  8bc
  928
    note: PC-relative expression @ 928
  934
  938
6c8
  6c8
  6e4
    note: PC-relative expression @ 6e4
  6f0
  704
  714
  728
  73c
  750
  764
  6f4
  76c
    note: PC-relative expression @ 76c
    note: PC-relative expression @ 778
a40
  a40
```
#### LLVM
```llvm
; ModuleID = 'complex-num.jv/bitcode/decompilation'
source_filename = "complex-num"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.CPUARMState = type { [16 x i32], [32 x i64], i64, i32, i32, i32, i32, [8 x i64], [8 x i32], [8 x i32], [5 x i32], [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, i64, [4 x i64], [4 x i64], %struct.anon.14.271, %struct.anon.45, %struct.anon.46, i32, i32, %struct.anon.47, i64, i64, i64, i64, i32, %struct.anon.48, i32, [16 x %struct.CPUBreakpoint*], [16 x %struct.CPUWatchpoint*], i64, %struct.anon.49, i8*, %struct.arm_boot_info* }
%struct.anon.14.271 = type { i32, %union.anon.15, %union.anon.15, i64, [4 x i64], i32, i64, i32, %union.anon.15, %union.anon.15, i64, [4 x %struct.TCR], %struct.TCR, i32, i32, %union.anon.23, i32, i32, i64, i64, %union.anon.23, %union.anon.15, [8 x i32], %union.anon.31, i64, %union.anon.15, i32, i32, i32, i64, i64, i32, i32, i32, i32, %union.anon.35, %union.anon.15, i32, %struct.EventNotifier, %union.anon.15, %union.anon.15, i64, i64, i64, %struct.QemuThread, i64, i64, i32, i64, [4 x %struct.Int128], i32, i32, i32, i32, i32, i32, i32, i32, i32, [16 x i64], [16 x i64], [16 x i64], [16 x i64], i64, i64, i64, i64, i64, i64, i64, i64 }
%struct.TCR = type { i64, i32, i32 }
%union.anon.23 = type { %struct.Int128 }
%struct.Int128 = type { i64, i64 }
%union.anon.31 = type { %struct.anon.32 }
%struct.anon.32 = type { i64, i32, i32, i32, i32, i64 }
%union.anon.35 = type { %struct.anon.36 }
%struct.anon.36 = type { i64, i32, i32, i64, i32, i32 }
%struct.EventNotifier = type { i32, i32 }
%union.anon.15 = type { %struct.anon.16.269 }
%struct.anon.16.269 = type { i64, i64, i64, i64 }
%struct.QemuThread = type { i64 }
%struct.anon.45 = type { i32, i32, i32, i32, i32, i32 }
%struct.anon.46 = type { i32, i32, i64, i32 }
%struct.anon.47 = type { [64 x i64], [16 x i32], i32, i32, [8 x i32], %struct.float_status, %struct.float_status }
%struct.float_status = type { i8, i8, i8, i8, i8, i8, i8 }
%struct.anon.48 = type { [16 x i64], i64, [16 x i32] }
%struct.CPUBreakpoint = type { i64, i32, %struct.anon.18 }
%struct.anon.18 = type { %struct.CPUBreakpoint*, %struct.CPUBreakpoint** }
%struct.CPUWatchpoint = type { i64, i64, i64, %struct.MemTxAttrs, i32, %struct.anon.19 }
%struct.MemTxAttrs = type { i24 }
%struct.anon.19 = type { %struct.CPUWatchpoint*, %struct.CPUWatchpoint** }
%struct.anon.49 = type { i32*, i32*, i32* }
%struct.arm_boot_info = type { i64, i8*, i8*, i8*, i8*, i64, i64, i64, i64, i32, i32, i8, i32 (%struct.arm_boot_info*, i8*)*, void (%struct.ARMCPU*, %struct.arm_boot_info*)*, void (%struct.ARMCPU*, %struct.arm_boot_info*)*, i8* (%struct.arm_boot_info*, i32*)*, void (%struct.arm_boot_info*, i8*)*, %struct.ArmLoadKernelNotifier, i32, i64, i64, i64, i8, i64, void (%struct.ARMCPU*, %struct.arm_boot_info*)*, i8, i32 }
%struct.ArmLoadKernelNotifier = type { %struct.Notifier, %struct.ARMCPU* }
%struct.Notifier = type { void (%struct.Notifier*, i8*)*, %struct.anon.5 }
%struct.anon.5 = type { %struct.Notifier*, %struct.Notifier** }
%struct.ARMCPU = type { %struct.CPUState, %struct.CPUARMState, %struct._GHashTable*, i64*, i64*, i32, i64*, i64*, i32, [4 x %struct.QEMUTimer*], [4 x %struct.IRQState*], %struct.MemoryRegion*, i8*, i32, i8, i8, i8, i8, i32, i32, i32, [7 x i32], i8, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i32, i64, [16 x i32], i64, i32, i8, i32, i64 }
%struct.CPUState = type { %struct.DeviceState, i32, i32, i32, %struct.QemuThread*, i32, i32, i8, %struct.QemuCond*, i8, i8, i8, i8, i8, i8, i32, i32, i64, [1 x %struct.__jmp_buf_tag], %struct.QemuMutex, %struct.qemu_work_item*, %struct.qemu_work_item*, %struct.CPUAddressSpace*, i32, %struct.AddressSpace*, %struct.MemoryRegion*, i8*, %struct.TranslationBlock*, [4096 x %struct.TranslationBlock*], %struct.GDBRegisterState*, i32, i32, %struct.anon.17, %struct.anon.18, %struct.anon.19, %struct.CPUWatchpoint*, i8*, i64, i64, i32, i8, %struct.KVMState*, %struct.kvm_run*, i32, i32, %union.anon.0, i32, i32, i8, i32 }
%struct.DeviceState = type { %struct.Object, i8*, i8, i8, %struct.QemuOpts*, i32, %struct.BusState*, %struct.anon.1, %struct.anon.3, i32, i32, i32 }
%struct.Object = type { %struct.ObjectClass*, void (i8*)*, %struct._GHashTable*, i32, %struct.Object* }
%struct.ObjectClass = type { %struct.TypeImpl*, %struct._GSList*, [4 x i8*], [4 x i8*], void (%struct.Object*)*, %struct._GHashTable* }
%struct.TypeImpl = type { i8*, i64, i64, void (%struct.ObjectClass*, i8*)*, void (%struct.ObjectClass*, i8*)*, void (%struct.ObjectClass*, i8*)*, i8*, void (%struct.Object*)*, void (%struct.Object*)*, void (%struct.Object*)*, i8, i8*, %struct.TypeImpl*, %struct.ObjectClass*, i32, [32 x %union.anon] }
%union.anon = type { i8* }
%struct._GSList = type { i8*, %struct._GSList* }
%struct.QemuOpts = type { i8*, %struct.QemuOptsList*, %struct.Location, %struct.anon.0.40, %struct.anon.38 }
%struct.QemuOptsList = type { i8*, i8*, i8, %struct.anon.38, [0 x %struct.QemuOptDesc] }
%struct.QemuOptDesc = type { i8*, i32, i8*, i8* }
%struct.Location = type { i32, i32, i8*, %struct.Location* }
%struct.anon.0.40 = type { %struct.QemuOpt*, %struct.QemuOpt** }
%struct.QemuOpt = type { i8*, i8*, %struct.QemuOptDesc*, %struct.QemuThread, %struct.QemuOpts*, %struct.anon.0.40 }
%struct.anon.38 = type { %struct.QemuOpts*, %struct.QemuOpts** }
%struct.BusState = type { %struct.Object, %struct.DeviceState*, i8*, %struct.FWPathProvider*, i32, i8, %struct.anon.59, %struct.anon.0 }
%struct.FWPathProvider = type { %struct.Object }
%struct.anon.59 = type { %struct.BusChild*, %struct.BusChild** }
%struct.BusChild = type { %struct.DeviceState*, i32, %struct.anon.59 }
%struct.anon.0 = type { %struct.BusState*, %struct.BusState** }
%struct.anon.1 = type { %struct.NamedGPIOList* }
%struct.NamedGPIOList = type { i8*, %struct.IRQState**, i32, i32, %struct.anon.2 }
%struct.IRQState = type { %struct.Object, void (i8*, i32, i32)*, i8*, i32 }
%struct.anon.2 = type { %struct.NamedGPIOList*, %struct.NamedGPIOList** }
%struct.anon.3 = type { %struct.BusState* }
%struct.QemuCond = type { %union.pthread_cond_t }
%union.pthread_cond_t = type { %struct.anon.7 }
%struct.anon.7 = type { %struct.QemuThread, %struct.QemuThread, [2 x i32], [2 x i32], i32, i32, [2 x i32] }
%struct.__jmp_buf_tag = type { [8 x i64], i32, %struct.__sigset_t }
%struct.__sigset_t = type { [16 x i64] }
%struct.QemuMutex = type { %union.pthread_mutex_t }
%union.pthread_mutex_t = type { %struct.__pthread_mutex_s }
%struct.__pthread_mutex_s = type { i32, i32, i32, i32, i32, i16, i16, %struct.__pthread_internal_list }
%struct.__pthread_internal_list = type { %struct.__pthread_internal_list*, %struct.__pthread_internal_list* }
%struct.qemu_work_item = type { %struct.qemu_work_item*, void (i8*)*, i8*, i32, i8 }
%struct.CPUAddressSpace = type opaque
%struct.AddressSpace = type { %struct.rcu_head, i8*, %struct.MemoryRegion*, i32, i8, %struct.FlatView*, i32, %struct.MemoryRegionIoeventfd*, %struct.AddressSpaceDispatch*, %struct.AddressSpaceDispatch*, %struct.MemoryListener, %struct.anon.16 }
%struct.rcu_head = type { %struct.rcu_head*, void (%struct.rcu_head*)* }
%struct.FlatView = type opaque
%struct.MemoryRegionIoeventfd = type opaque
%struct.AddressSpaceDispatch = type opaque
%struct.MemoryListener = type { void (%struct.MemoryListener*)*, void (%struct.MemoryListener*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i32, i32)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i32, i32)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*)*, void (%struct.MemoryListener*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i1, i64, %struct.EventNotifier*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i1, i64, %struct.EventNotifier*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i64, i64)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i64, i64)*, i32, %struct.AddressSpace*, %struct.anon.15 }
%struct.MemoryRegionSection = type { %struct.MemoryRegion*, %struct.AddressSpace*, i64, %struct.Int128, i64, i8 }
%struct.anon.15 = type { %struct.MemoryListener*, %struct.MemoryListener** }
%struct.anon.16 = type { %struct.AddressSpace*, %struct.AddressSpace** }
%struct.TranslationBlock = type { i64, i64, i64, i16, i16, i32, i8*, i8*, %struct.TranslationBlock*, %struct.TranslationBlock*, [2 x %struct.TranslationBlock*], [2 x i64], [2 x i16], [2 x i16], [2 x %struct.TranslationBlock*], %struct.TranslationBlock* }
%struct.GDBRegisterState = type { i32, i32, i32 (%struct.CPUARMState*, i8*, i32)*, i32 (%struct.CPUARMState*, i8*, i32)*, i8*, %struct.GDBRegisterState* }
%struct.anon.17 = type { %struct.CPUState*, %struct.CPUState** }
%struct.KVMState = type opaque
%struct.kvm_run = type opaque
%union.anon.0 = type { i32 }
%struct._GHashTable = type opaque
%struct.QEMUTimer = type { i64, %struct.QEMUTimerList*, void (i8*)*, i8*, %struct.QEMUTimer*, i32 }
%struct.QEMUTimerList = type opaque
%struct.MemoryRegion = type { %struct.Object, i8, i8, i8, i8, i8, i8, i8, i8, %struct.RAMBlock*, %struct.Object*, %struct.MemoryRegionIOMMUOps*, %struct.MemoryRegionOps*, i8*, %struct.MemoryRegion*, %struct.Int128, i64, void (%struct.MemoryRegion*)*, i64, i8, i8, i8, i8, i8, %struct.MemoryRegion*, i64, i32, i8, %struct.subregions, %struct.subregions, %struct.coalesced_ranges, i8*, i32, %struct.MemoryRegionIoeventfd*, %struct.NotifierList }
%struct.RAMBlock = type opaque
%struct.MemoryRegionIOMMUOps = type { void (%struct.IOMMUTLBEntry*, %struct.MemoryRegion*, i64, i1)* }
%struct.IOMMUTLBEntry = type { %struct.AddressSpace*, i64, i64, i64, i32 }
%struct.MemoryRegionOps = type { i64 (i8*, i64, i32)*, void (i8*, i64, i64, i32)*, i32 (i8*, i64, i64*, i32, i32)*, i32 (i8*, i64, i64, i32, i32)*, i32, %struct.anon.11, %struct.anon.12, %struct.MemoryRegionMmio }
%struct.anon.11 = type { i32, i32, i8, i1 (i8*, i64, i32, i1)* }
%struct.anon.12 = type { i32, i32, i8 }
%struct.MemoryRegionMmio = type { [3 x i32 (i8*, i64)*], [3 x void (i8*, i64, i32)*] }
%struct.subregions = type { %struct.MemoryRegion*, %struct.MemoryRegion** }
%struct.coalesced_ranges = type { %struct.CoalescedMemoryRange*, %struct.CoalescedMemoryRange** }
%struct.CoalescedMemoryRange = type opaque
%struct.NotifierList = type { %struct.anon.14 }
%struct.anon.14 = type { %struct.Notifier* }
%struct.__jove_sections = type <{ %struct.__jove__interp, [1 x i8], %struct.__jove__note_ABI-tag, %struct.__jove__note_gnu_build-id, %struct.__jove__dynsym, %struct.__jove__dynstr, [7 x i8], %struct.__jove__gnu_hash, %struct.__jove__gnu_version, [2 x i8], %struct.__jove__gnu_version_r, [4 x i8], %struct.__jove__rela_dyn, %struct.__jove__rela_plt, %struct.__jove__init, [4 x i8], %struct.__jove__plt, %struct.__jove__text, %struct.__jove__fini, [4 x i8], %struct.__jove__rodata, %struct.__jove__eh_frame, %struct.__jove__eh_frame_hdr, [4096 x i8], %struct.__jove__dynamic, %struct.__jove__got, %struct.__jove__got_plt, %struct.__jove__data, %struct.__jove__jcr, %struct.__jove__fini_array, %struct.__jove__init_array, %struct.__jove__bss }>
%struct.__jove__interp = type <{ [27 x i8] }>
%struct.__jove__note_ABI-tag = type <{ [32 x i8] }>
%struct.__jove__note_gnu_build-id = type <{ [36 x i8] }>
%struct.__jove__dynsym = type <{ [264 x i8] }>
%struct.__jove__dynstr = type <{ [169 x i8] }>
%struct.__jove__gnu_hash = type <{ [28 x i8] }>
%struct.__jove__gnu_version = type <{ [22 x i8] }>
%struct.__jove__gnu_version_r = type <{ [32 x i8] }>
%struct.__jove__rela_dyn = type <{ [264 x i8] }>
%struct.__jove__rela_plt = type <{ [168 x i8] }>
%struct.__jove__init = type <{ [20 x i8] }>
%struct.__jove__plt = type <{ [144 x i8] }>
%struct.__jove__text = type <{ [892 x i8] }>
%struct.__jove__fini = type <{ [16 x i8] }>
%struct.__jove__rodata = type <{ [68 x i8] }>
%struct.__jove__eh_frame = type <{ [4 x i8] }>
%struct.__jove__eh_frame_hdr = type <{ [8 x i8] }>
%struct.__jove__dynamic = type <{ [480 x i8] }>
%struct.__jove__got = type <{ [8 x i8], i64*, i64*, i64*, void ()*, void ()*, void ()*, void ()*, void ()* }>
%struct.__jove__got_plt = type <{ [24 x i8], void ()*, void ()*, void ()*, void ()*, void ()*, void ()*, void ()* }>
%struct.__jove__data = type <{ [8 x i8], i64* }>
%struct.__jove__jcr = type <{ [8 x i8] }>
%struct.__jove__fini_array = type <{ i64* }>
%struct.__jove__init_array = type <{ i64* }>
%struct.__jove__bss = type <{ [1 x i8] }>

@cpu_state = external thread_local local_unnamed_addr global %struct.CPUARMState
@__jove_sections = global %struct.__jove_sections <{ %struct.__jove__interp <{ [27 x i8] c"/lib/ld-linux-aarch64.so.1\00" }>, [1 x i8] zeroinitializer, %struct.__jove__note_ABI-tag <{ [32 x i8] c"\04\00\00\00\10\00\00\00\01\00\00\00GNU\00\00\00\00\00\03\00\00\00\07\00\00\00\00\00\00\00" }>, %struct.__jove__note_gnu_build-id <{ [36 x i8] c"\04\00\00\00\14\00\00\00\03\00\00\00GNU\00Q\DC\94\8CF!R\5Ce\B3Hx\F9\9A\F5\A6\11\A2\D6D" }>, %struct.__jove__dynsym <{ [264 x i8] c"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\1D\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00#\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00*\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00<\00\00\00\22\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00K\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00Z\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00_\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00{\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\95\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__dynstr <{ [169 x i8] c"\00printf\00GLIBC_2.17\00libc.so.6\00abort\00strtol\00__libc_start_main\00__cxa_finalize\00__gmon_start__\00puts\00_ITM_deregisterTMCloneTable\00_ITM_registerTMCloneTable\00_Jv_RegisterClasses\00" }>, [7 x i8] zeroinitializer, %struct.__jove__gnu_hash <{ [28 x i8] c"\01\00\00\00\0B\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__gnu_version <{ [22 x i8] c"\00\00\02\00\02\00\02\00\02\00\02\00\00\00\02\00\00\00\00\00\00\00" }>, [2 x i8] zeroinitializer, %struct.__jove__gnu_version_r <{ [32 x i8] c"\01\00\01\00\13\00\00\00\10\00\00\00\00\00\00\00\97\91\96\06\00\00\02\00\08\00\00\00\00\00\00\00" }>, [4 x i8] zeroinitializer, %struct.__jove__rela_dyn <{ [264 x i8] c"\90\1C\00\00\00\00\00\00\03\04\00\00\00\00\00\00\C8\06\00\00\00\00\00\00\98\1C\00\00\00\00\00\00\03\04\00\00\00\00\00\00\C8\09\00\00\00\00\00\00\A0\1C\00\00\00\00\00\00\03\04\00\00\00\00\00\00@\0A\00\00\00\00\00\00(\1D\00\00\00\00\00\00\03\04\00\00\00\00\00\00(\1D\00\00\00\00\00\008\1D\00\00\00\00\00\00\03\04\00\00\00\00\00\00\C0\08\00\00\00\00\00\00@\1D\00\00\00\00\00\00\03\04\00\00\00\00\00\00\08\09\00\00\00\00\00\00\C0\1C\00\00\00\00\00\00\01\04\00\00\05\00\00\00\00\00\00\00\00\00\00\00\A8\1C\00\00\00\00\00\00\01\04\00\00\06\00\00\00\00\00\00\00\00\00\00\00\B0\1C\00\00\00\00\00\00\01\04\00\00\08\00\00\00\00\00\00\00\00\00\00\00\B8\1C\00\00\00\00\00\00\01\04\00\00\09\00\00\00\00\00\00\00\00\00\00\00\C8\1C\00\00\00\00\00\00\01\04\00\00\0A\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__rela_plt <{ [168 x i8] c"\E8\1C\00\00\00\00\00\00\02\04\00\00\04\00\00\00\00\00\00\00\00\00\00\00\F0\1C\00\00\00\00\00\00\02\04\00\00\02\00\00\00\00\00\00\00\00\00\00\00\F8\1C\00\00\00\00\00\00\02\04\00\00\06\00\00\00\00\00\00\00\00\00\00\00\00\1D\00\00\00\00\00\00\02\04\00\00\05\00\00\00\00\00\00\00\00\00\00\00\08\1D\00\00\00\00\00\00\02\04\00\00\07\00\00\00\00\00\00\00\00\00\00\00\10\1D\00\00\00\00\00\00\02\04\00\00\03\00\00\00\00\00\00\00\00\00\00\00\18\1D\00\00\00\00\00\00\02\04\00\00\01\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__init <{ [20 x i8] c"\FD{\BF\A9\FD\03\00\91\86\00\00\94\FD{\C1\A8\C0\03_\D6" }>, [4 x i8] zeroinitializer, %struct.__jove__plt <{ [144 x i8] c"\F0{\BF\A9\10\00\00\B0\11rF\F9\10\823\91 \02\1F\D6\1F \03\D5\1F \03\D5\1F \03\D5\10\00\00\B0\11vF\F9\10\A23\91 \02\1F\D6\10\00\00\B0\11zF\F9\10\C23\91 \02\1F\D6\10\00\00\B0\11~F\F9\10\E23\91 \02\1F\D6\10\00\00\B0\11\82F\F9\10\024\91 \02\1F\D6\10\00\00\B0\11\86F\F9\10\224\91 \02\1F\D6\10\00\00\B0\11\8AF\F9\10B4\91 \02\1F\D6\10\00\00\B0\11\8EF\F9\10b4\91 \02\1F\D6" }>, %struct.__jove__text <{ [892 x i8] c"\FD{\BD\A9\1F\18\00q\FD\03\00\91\F3S\01\A9\F5[\02\A9\F3\03\01\AA \01\00T\00\00\00\90\00\A0)\91\EB\FF\FF\97\00\00\80R\F3SA\A9\F5[B\A9\FD{\C3\A8\C0\03_\D6 \04@\F9B\01\80R\01\00\80\D2\E6\FF\FF\97\F5\03\00\AA`\0A@\F9B\01\80R\01\00\80\D2\E1\FF\FF\97\F4\03\00\AA`\12@\F9B\01\80R\01\00\80\D2\DC\FF\FF\97\F6\03\00\AA`\16@\F9B\01\80R\01\00\80\D2\D7\FF\FF\97d\0E@\F9\84\00@9\84\A8\00Q\9F\14\00qi\00\00T \00\80R\E3\FF\FF\17\05\00\00\90\A5p)\91\A1Hd8b\00\00\10A\88!\8B \00\1F\D6\E2\03\16\AA\E3\03\00\AA\E1\03\14\AA\E0\03\15\AA\84\00\00\94\E2\03\01\AA\E1\03\00\AA\00\00\00\90\00@*\91\C4\FF\FF\97\00\00\80R\D1\FF\FF\17\E2\03\16\AA\E3\03\00\AA\E1\03\14\AA\E0\03\15\AAh\00\00\94\E2\03\01\AA\F4\FF\FF\17\E2\03\16\AA\E3\03\00\AA\E1\03\14\AA\E0\03\15\AAW\00\00\94\E2\03\01\AA\ED\FF\FF\17\E2\03\16\AA\E3\03\00\AA\E1\03\14\AA\E0\03\15\AAd\00\00\94\E2\03\01\AA\E6\FF\FF\17\1D\00\80\D2\1E\00\80\D2\E5\03\00\AA\E1\03@\F9\E2#\00\91\E6\03\00\91\00\00\00\B0\00HF\F9\03\00\00\B0cLF\F9\04\00\00\B0\84PF\F9\88\FF\FF\97\8B\FF\FF\97\00\00\00\B0\00TF\F9@\00\00\B4\8B\FF\FF\17\C0\03_\D6\01\00\00\B0\00\00\00\B0!\E04\91\00\E04\91!\1C\00\91!\00\00\CB?8\00\F1\A9\00\00T\01\00\00\B0!XF\F9A\00\00\B4 \00\1F\D6\C0\03_\D6\00\00\00\B0\01\00\00\B0\00\E04\91!\E04\91!\00\00\CB\22\FCC\93B\FCB\8BA\FCA\93\A1\00\00\B4\02\00\00\B0B\5CF\F9B\00\00\B4@\00\1F\D6\C0\03_\D6\FD{\BE\A9\FD\03\00\91\F3\0B\00\F9\13\00\00\B0`\22u9@\01\005\00\00\00\B0\00`F\F9\80\00\00\B4\00\00\00\B0\00\94F\F9g\FF\FF\97\D9\FF\FF\97 \00\80R`\2259\F3\0B@\F9\FD{\C2\A8\C0\03_\D6\FD{\BF\A9\00\00\00\B0\FD\03\00\91\00\C04\91\01\00@\F9a\00\00\B5\FD{\C1\A8\D9\FF\FF\17\01\00\00\B0!dF\F9\81\FF\FF\B4 \00?\D6\FA\FF\FF\17\FF\C3\00\D1\E0\07\01\A9\E2\0F\00\A9\E0\07\C0=\E1\03\C0=\00\84\E1N\E0\0B\80=\E0\07B\A9\FF\C3\00\91\C0\03_\D6\FF\C3\00\D1\E0\07\01\A9\E2\0F\00\A9\E0\07\C0=\E1\03\C0=\00\84\E1n\E0\0B\80=\E0\07B\A9\FF\C3\00\91\C0\03_\D6F|\00\9B\E5\03\01\AAa|\00\9BA\04\05\9B`\98\05\9B\C0\03_\D6F|\01\9Be|\01\9Bd|\03\9BA\10\02\9Bc\98\00\9BB\14\00\9B@\0C\C1\9Aa\0C\C1\9A\C0\03_\D6\FD{\BC\A9\FD\03\00\91\F3S\01\A9\F7c\03\A9\14\00\00\B0\18\00\00\B0\18\035\91\94\225\91\94\02\18\CB\94\FEC\93\F5[\02\A9\F7\03\00*\F6\03\01\AA\F5\03\02\AA\13\00\80\D2\07\FF\FF\974\01\00\B4\03{s\F8\E0\03\17*\E1\03\16\AA\E2\03\15\AA`\00?\D6s\06\00\91\7F\02\14\EB!\FF\FFT\F3SA\A9\F5[B\A9\F7cC\A9\FD{\C4\A8\C0\03_\D6\C0\03_\D6" }>, %struct.__jove__fini <{ [16 x i8] c"\FD{\BF\A9\FD\03\00\91\FD{\C1\A8\C0\03_\D6" }>, [4 x i8] zeroinitializer, %struct.__jove__rodata <{ [68 x i8] c"\01\00\02\00\1A\13\F8\0C\F8\00\00\00\00\00\00\00usage: complex-num w x [+-*/] y z\00\00\00\00\00\00\00%li + %lii\0A\00" }>, %struct.__jove__eh_frame zeroinitializer, %struct.__jove__eh_frame_hdr <{ [8 x i8] c"\01\1B\FF\FF\F8\FF\FF\FF" }>, [4096 x i8] zeroinitializer, %struct.__jove__dynamic <{ [480 x i8] c"\03\00\00\00\00\00\00\00\D0\1C\00\00\00\00\00\00\02\00\00\00\00\00\00\00\A8\00\00\00\00\00\00\00\17\00\00\00\00\00\00\00x\05\00\00\00\00\00\00\14\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00p\04\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\01\00\00\00\00\00\00\09\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\F9\FF\FFo\00\00\00\00\06\00\00\00\00\00\00\00\15\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\06\00\00\00\00\00\00\00`\02\00\00\00\00\00\00\0B\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00h\03\00\00\00\00\00\00\0A\00\00\00\00\00\00\00\A9\00\00\00\00\00\00\00\F5\FE\FFo\00\00\00\00\18\04\00\00\00\00\00\00\01\00\00\00\00\00\00\00\13\00\00\00\00\00\00\00\0C\00\00\00\00\00\00\00 \06\00\00\00\00\00\00\0D\00\00\00\00\00\00\00D\0A\00\00\00\00\00\00\1A\00\00\00\00\00\00\008\1D\00\00\00\00\00\00\1C\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\19\00\00\00\00\00\00\00@\1D\00\00\00\00\00\00\1B\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\F0\FF\FFo\00\00\00\004\04\00\00\00\00\00\00\FE\FF\FFo\00\00\00\00L\04\00\00\00\00\00\00\FF\FF\FFo\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__got <{ [8 x i8] c"\A8\1A\00\00\00\00\00\00", i64* bitcast (%struct.__jove__text* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17) to i64*), i64* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 768) to i64*), i64* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 888) to i64*), void ()* @__gmon_start__, void ()* @_ITM_deregisterTMCloneTable, void ()* @_ITM_registerTMCloneTable, void ()* @__cxa_finalize, void ()* @_Jv_RegisterClasses }>, %struct.__jove__got_plt <{ [24 x i8] zeroinitializer, void ()* @__libc_start_main, void ()* @abort, void ()* @__gmon_start__, void ()* @__cxa_finalize, void ()* @puts, void ()* @strtol, void ()* @printf }>, %struct.__jove__data <{ [8 x i8] zeroinitializer, i64* bitcast (i64** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 27, i32 1) to i64*) }>, %struct.__jove__jcr zeroinitializer, %struct.__jove__fini_array <{ i64* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 504) to i64*) }>, %struct.__jove__init_array <{ i64* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 576) to i64*) }>, %struct.__jove__bss zeroinitializer }>, align 4096

declare extern_weak void @__cxa_finalize()

declare extern_weak void @__gmon_start__()

declare extern_weak void @_ITM_deregisterTMCloneTable()

declare extern_weak void @_ITM_registerTMCloneTable()

declare extern_weak void @_Jv_RegisterClasses()

declare void @__libc_start_main()

declare void @abort()

declare void @puts()

declare void @strtol()

declare void @printf()

; Function Attrs: noinline
define internal void @"0x688"() local_unnamed_addr #0 {
"0x688":
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 4) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__cxa_finalize to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* @__cxa_finalize)
  ret void
}

; Function Attrs: noinline
define internal void @"0x668"() local_unnamed_addr #0 {
"0x668":
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 2) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @abort to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @abort)
  ret void
}

; Function Attrs: noinline norecurse nounwind readnone
define { i64, i64, i64, i64, i64, i64, i64 } @cn_div(i64 %x0, i64 %x1, i64 %x2, i64 %x3) local_unnamed_addr #1 {
"0x9a4":
  %0 = mul i64 %x2, %x1
  %1 = mul i64 %x3, %x1
  %2 = mul i64 %x3, %x3
  %3 = mul i64 %x2, %x2
  %4 = add i64 %2, %3
  %5 = mul i64 %x3, %x0
  %6 = sub i64 %0, %5
  %7 = mul i64 %x2, %x0
  %8 = add i64 %1, %7
  %9 = tail call i64 @helper_sdiv64(i64 %6, i64 %4)
  %10 = tail call i64 @helper_sdiv64(i64 %8, i64 %4)
  %11 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } undef, i64 %10, 0
  %12 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %11, i64 %9, 1
  %13 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %12, i64 %8, 2
  %14 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %13, i64 %6, 3
  %15 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %14, i64 %2, 4
  %16 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %15, i64 %1, 5
  %17 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %16, i64 %0, 6
  ret { i64, i64, i64, i64, i64, i64, i64 } %17
}

; Function Attrs: noinline
define { i64 } @_start(i64 %x0) local_unnamed_addr #0 {
"0x808":
  %sp_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_1, 8
  %1 = inttoptr i64 %sp_1 to i64*
  %2 = load i64, i64* %1, align 8, !noalias !0
  store i64 ptrtoint (%struct.__jove__text* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 %2, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 2), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 768) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 3), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 888) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 4), align 8, !alias.scope !0
  store i64 %x0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 5), align 8, !alias.scope !0
  store i64 %sp_1, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  tail call void @"0x658"()
  tail call void @"0x668"()
  br i1 icmp eq (void ()* @__gmon_start__, void ()* null), label %"0x850.exit", label %"0x678"

"0x678":                                          ; preds = %"0x808"
  store i64 ptrtoint (void ()* @__gmon_start__ to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 3) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__gmon_start__ to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* @__gmon_start__)
  ret { i64 } undef

"0x850.exit":                                     ; preds = %"0x808"
  ret { i64 } zeroinitializer
}

; Function Attrs: noinline
define void @__libc_csu_init(i64 %x0, i64 %x1, i64 %x2) local_unnamed_addr #0 {
"0x9c8":
  %x19_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %x20_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  %x21_3 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  %x22_4 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  %x23_5 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 23), align 8, !alias.scope !0
  %x24_6 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 24), align 8, !alias.scope !0
  %x29_7 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %lr_8 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 30), align 8, !alias.scope !0
  %sp_9 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_9, -64
  %1 = inttoptr i64 %0 to i64*
  store i64 %x29_7, i64* %1, align 8, !noalias !0
  %2 = add i64 %sp_9, -56
  %3 = inttoptr i64 %2 to i64*
  store i64 %lr_8, i64* %3, align 8, !noalias !0
  %4 = add i64 %sp_9, -48
  %5 = inttoptr i64 %4 to i64*
  store i64 %x19_1, i64* %5, align 8, !noalias !0
  %6 = add i64 %sp_9, -40
  %7 = inttoptr i64 %6 to i64*
  store i64 %x20_2, i64* %7, align 8, !noalias !0
  %8 = add i64 %sp_9, -16
  %9 = inttoptr i64 %8 to i64*
  store i64 %x23_5, i64* %9, align 8, !noalias !0
  %10 = add i64 %sp_9, -8
  %11 = inttoptr i64 %10 to i64*
  store i64 %x24_6, i64* %11, align 8, !noalias !0
  %12 = add i64 %sp_9, -32
  %13 = inttoptr i64 %12 to i64*
  store i64 %x21_3, i64* %13, align 8, !noalias !0
  %14 = add i64 %sp_9, -24
  %15 = inttoptr i64 %14 to i64*
  store i64 %x22_4, i64* %15, align 8, !noalias !0
  %16 = and i64 %x0, 4294967295
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 1, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  store i64 %x2, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  store i64 %x1, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  store i64 %16, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 23), align 8, !alias.scope !0
  store i64 ptrtoint (%struct.__jove__init_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 24), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  tail call void @_init()
  %x20_11 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  %x24_15 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 24), align 8, !alias.scope !0
  %sp_16 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %not. = icmp eq i64 %x20_11, 0
  br i1 %not., label %"0xa2c.exit", label %"0xa0c.preheader"

"0xa0c.preheader":                                ; preds = %"0x9c8"
  %x19_10 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  br label %"0xa0c"

"0xa0c":                                          ; preds = %"0xa0c", %"0xa0c.preheader"
  %x19_.0 = phi i64 [ %21, %"0xa0c" ], [ %x19_10, %"0xa0c.preheader" ]
  %17 = shl i64 %x19_.0, 3
  %18 = add i64 %17, %x24_15
  %19 = inttoptr i64 %18 to void ()**
  %20 = load void ()*, void ()** %19, align 8, !noalias !0
  tail call void @__jove_indirect_call(void ()* %20)
  %21 = add i64 %x19_.0, 1
  %22 = sub i64 %21, %x20_11
  %23 = lshr i64 %22, 32
  %24 = or i64 %23, %22
  %25 = trunc i64 %24 to i32
  %26 = icmp eq i32 %25, 0
  br i1 %26, label %"0xa2c.exit.loopexit", label %"0xa0c"

"0xa2c.exit.loopexit":                            ; preds = %"0xa0c"
  %27 = trunc i64 %23 to i32
  %28 = icmp uge i64 %21, %x20_11
  %29 = zext i1 %28 to i32
  %30 = xor i64 %22, %21
  %31 = xor i64 %21, %x20_11
  %32 = and i64 %30, %31
  %33 = lshr i64 %32, 32
  %34 = trunc i64 %33 to i32
  br label %"0xa2c.exit"

"0xa2c.exit":                                     ; preds = %"0xa2c.exit.loopexit", %"0x9c8"
  %VF_.0 = phi i32 [ undef, %"0x9c8" ], [ %34, %"0xa2c.exit.loopexit" ]
  %NF_.0 = phi i32 [ undef, %"0x9c8" ], [ %27, %"0xa2c.exit.loopexit" ]
  %CF_.0 = phi i32 [ undef, %"0x9c8" ], [ %29, %"0xa2c.exit.loopexit" ]
  %35 = add i64 %sp_16, 48
  %36 = add i64 %sp_16, 32
  %37 = add i64 %sp_16, 16
  %38 = add i64 %sp_16, 64
  %39 = inttoptr i64 %sp_16 to i64*
  %40 = load i64, i64* %39, align 8, !noalias !0
  %41 = add i64 %sp_16, 56
  %42 = inttoptr i64 %41 to i64*
  %43 = load i64, i64* %42, align 8, !noalias !0
  %44 = inttoptr i64 %35 to i64*
  %45 = load i64, i64* %44, align 8, !noalias !0
  %46 = add i64 %sp_16, 40
  %47 = inttoptr i64 %46 to i64*
  %48 = load i64, i64* %47, align 8, !noalias !0
  %49 = inttoptr i64 %36 to i64*
  %50 = load i64, i64* %49, align 8, !noalias !0
  %51 = add i64 %sp_16, 24
  %52 = inttoptr i64 %51 to i64*
  %53 = load i64, i64* %52, align 8, !noalias !0
  %54 = inttoptr i64 %37 to i64*
  %55 = load i64, i64* %54, align 8, !noalias !0
  store i32 %CF_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %NF_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %VF_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  store i64 %55, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %53, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  store i64 %50, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  store i64 %48, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  store i64 %45, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 23), align 8, !alias.scope !0
  store i64 %43, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 24), align 8, !alias.scope !0
  store i64 %40, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %38, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  ret void
}

; Function Attrs: noinline
define internal void @"0x658"() local_unnamed_addr #0 {
"0x658":
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 1) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__libc_start_main to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @__libc_start_main)
  ret void
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_add(i64 %x0, i64 %x1, i64 %x2, i64 %x3) local_unnamed_addr #2 {
"0x93c":
  %sp_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_2, -48
  %1 = add i64 %sp_2, -32
  %2 = inttoptr i64 %1 to i64*
  store i64 %x0, i64* %2, align 8, !noalias !0
  %3 = add i64 %sp_2, -24
  %4 = inttoptr i64 %3 to i64*
  store i64 %x1, i64* %4, align 8, !noalias !0
  %5 = inttoptr i64 %0 to i64*
  store i64 %x2, i64* %5, align 8, !noalias !0
  %6 = add i64 %sp_2, -40
  %7 = inttoptr i64 %6 to i64*
  store i64 %x3, i64* %7, align 8, !noalias !0
  %8 = load i64, i64* %2, align 8, !noalias !0
  %9 = load i64, i64* %4, align 8
  %10 = load i64, i64* %5, align 8, !noalias !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 2), align 8, !alias.scope !0
  store i64 %x3, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 3), align 8, !alias.scope !0
  %11 = add i64 %10, %8
  store i64 %11, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 0), align 8, !alias.scope !0
  %12 = add i64 %9, %x3
  store i64 %12, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 1), align 8, !alias.scope !0
  %13 = add i64 %sp_2, -16
  %14 = add i64 %sp_2, -8
  %15 = inttoptr i64 %13 to i64*
  store i64 %11, i64* %15, align 8, !noalias !0
  %16 = inttoptr i64 %14 to i64*
  store i64 %12, i64* %16, align 8, !noalias !0
  %17 = load i64, i64* %15, align 8, !noalias !0
  %18 = insertvalue { i64, i64 } undef, i64 %17, 0
  %19 = insertvalue { i64, i64 } %18, i64 %12, 1
  ret { i64, i64 } %19
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_sub(i64 %x0, i64 %x1, i64 %x2, i64 %x3) local_unnamed_addr #2 {
"0x964":
  %sp_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_2, -48
  %1 = add i64 %sp_2, -32
  %2 = inttoptr i64 %1 to i64*
  store i64 %x0, i64* %2, align 8, !noalias !0
  %3 = add i64 %sp_2, -24
  %4 = inttoptr i64 %3 to i64*
  store i64 %x1, i64* %4, align 8, !noalias !0
  %5 = inttoptr i64 %0 to i64*
  store i64 %x2, i64* %5, align 8, !noalias !0
  %6 = add i64 %sp_2, -40
  %7 = inttoptr i64 %6 to i64*
  store i64 %x3, i64* %7, align 8, !noalias !0
  %8 = load i64, i64* %2, align 8, !noalias !0
  %9 = load i64, i64* %4, align 8
  %10 = load i64, i64* %5, align 8, !noalias !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 2), align 8, !alias.scope !0
  store i64 %x3, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 3), align 8, !alias.scope !0
  %11 = sub i64 %8, %10
  store i64 %11, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 0), align 8, !alias.scope !0
  %12 = sub i64 %9, %x3
  store i64 %12, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 1), align 8, !alias.scope !0
  %13 = add i64 %sp_2, -16
  %14 = add i64 %sp_2, -8
  %15 = inttoptr i64 %13 to i64*
  store i64 %11, i64* %15, align 8, !noalias !0
  %16 = inttoptr i64 %14 to i64*
  store i64 %12, i64* %16, align 8, !noalias !0
  %17 = load i64, i64* %15, align 8, !noalias !0
  %18 = insertvalue { i64, i64 } undef, i64 %17, 0
  %19 = insertvalue { i64, i64 } %18, i64 %12, 1
  ret { i64, i64 } %19
}

; Function Attrs: noinline
define internal void @"0x698"() local_unnamed_addr #0 {
"0x698":
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 5) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @puts to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @puts)
  ret void
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @deregister_tm_clones() local_unnamed_addr #2 {
"0x854":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 -1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 -1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  ret { i64, i64 } { i64 ptrtoint (%struct.__jove__fini_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 29) to i64), i64 7 }
}

; Function Attrs: noinline
define void @_init() local_unnamed_addr #0 {
"0x620":
  %x29_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %lr_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 30), align 8, !alias.scope !0
  %sp_3 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_3, -16
  %1 = inttoptr i64 %0 to i64*
  store i64 %x29_1, i64* %1, align 8, !noalias !0
  %2 = add i64 %sp_3, -8
  %3 = inttoptr i64 %2 to i64*
  store i64 %lr_2, i64* %3, align 8, !noalias !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %4 = tail call { i64 } @call_weak_fn()
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  %sp_4 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %5 = add i64 %sp_4, 16
  %6 = inttoptr i64 %sp_4 to i64*
  %7 = load i64, i64* %6, align 8, !noalias !0
  store i64 %7, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %5, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  ret void
}

; Function Attrs: noinline
define { i64 } @call_weak_fn() local_unnamed_addr #0 {
"0x840":
  br i1 icmp eq (void ()* @__gmon_start__, void ()* null), label %"0x850.exit", label %"0x678"

"0x678":                                          ; preds = %"0x840"
  store i64 ptrtoint (void ()* @__gmon_start__ to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 3) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__gmon_start__ to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* @__gmon_start__)
  ret { i64 } undef

"0x850.exit":                                     ; preds = %"0x840"
  ret { i64 } zeroinitializer
}

; Function Attrs: noinline norecurse nounwind
define void @_fini() local_unnamed_addr #2 {
"0xa44":
  %x29_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %lr_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 30), align 8, !alias.scope !0
  %sp_3 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_3, -16
  %1 = inttoptr i64 %0 to i64*
  store i64 %x29_1, i64* %1, align 8, !noalias !0
  %2 = add i64 %sp_3, -8
  %3 = inttoptr i64 %2 to i64*
  store i64 %lr_2, i64* %3, align 8, !noalias !0
  %4 = load i64, i64* %1, align 8, !noalias !0
  store i64 %4, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  ret void
}

; Function Attrs: noinline norecurse nounwind readnone
define { i64, i64, i64 } @register_tm_clones() local_unnamed_addr #1 {
"0x888":
  ret { i64, i64, i64 } { i64 ptrtoint (%struct.__jove__fini_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 29) to i64), i64 0, i64 0 }
}

; Function Attrs: noinline
define internal void @"0x6a8"() local_unnamed_addr #0 {
"0x6a8":
  store i64 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26, i32 6) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 16), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @strtol to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 17), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @strtol)
  ret void
}

; Function Attrs: noinline norecurse nounwind readnone
define { i64, i64, i64, i64 } @cn_mul(i64 %x0, i64 %x1, i64 %x2, i64 %x3) local_unnamed_addr #1 {
"0x98c":
  %0 = mul i64 %x2, %x0
  %1 = mul i64 %x3, %x1
  %2 = sub i64 %0, %1
  %3 = mul i64 %x3, %x0
  %4 = mul i64 %x2, %x1
  %5 = add i64 %3, %4
  %6 = insertvalue { i64, i64, i64, i64 } undef, i64 %2, 0
  %7 = insertvalue { i64, i64, i64, i64 } %6, i64 %5, 1
  %8 = insertvalue { i64, i64, i64, i64 } %7, i64 %x1, 2
  %9 = insertvalue { i64, i64, i64, i64 } %8, i64 %0, 3
  ret { i64, i64, i64, i64 } %9
}

; Function Attrs: noinline
define { i64 } @__do_global_dtors_aux() local_unnamed_addr #0 {
"0x8c0":
  %x19_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %x29_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %lr_3 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 30), align 8, !alias.scope !0
  %sp_4 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_4, -32
  %1 = inttoptr i64 %0 to i64*
  store i64 %x29_2, i64* %1, align 8, !noalias !0
  %2 = add i64 %sp_4, -24
  %3 = inttoptr i64 %2 to i64*
  store i64 %lr_3, i64* %3, align 8, !noalias !0
  %4 = add i64 %sp_4, -16
  %5 = inttoptr i64 %4 to i64*
  store i64 %x19_1, i64* %5, align 8, !noalias !0
  %6 = load i64, i64* bitcast (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 31) to i64*), align 8, !noalias !0
  %7 = and i64 %6, 4294967295
  %8 = icmp eq i64 %7, 0
  br i1 %8, label %"0x8d8", label %"0x8fc.exit"

"0x8d8":                                          ; preds = %"0x8c0"
  br i1 icmp eq (void ()* @__cxa_finalize, void ()* null), label %"0x8f0.exit", label %"0x8e4"

"0x8e4":                                          ; preds = %"0x8d8"
  store i64 ptrtoint (i64** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 27, i32 1) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 23, i64 1368) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  tail call void @"0x688"()
  %x19_10 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %sp_11 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  br label %"0x8f0.exit"

"0x8f0.exit":                                     ; preds = %"0x8e4", %"0x8d8"
  %sp_.0 = phi i64 [ %sp_11, %"0x8e4" ], [ %0, %"0x8d8" ]
  %x19_.0 = phi i64 [ %x19_10, %"0x8e4" ], [ ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 23, i64 1368) to i64), %"0x8d8" ]
  %x0_.0 = phi i64 [ ptrtoint (i64** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 27, i32 1) to i64), %"0x8e4" ], [ 0, %"0x8d8" ]
  store i64 %x0_.0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 %x19_.0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %sp_.0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %9 = tail call { i64, i64 } @deregister_tm_clones()
  store i64 ptrtoint (%struct.__jove__fini_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 29) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 7, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  %sp_13 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %x19_12 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %10 = add i64 %x19_12, 3400
  %11 = inttoptr i64 %10 to i64*
  store i64 1, i64* %11, align 8, !noalias !0
  %12 = add i64 %sp_13, 32
  %13 = inttoptr i64 %sp_13 to i64*
  %14 = load i64, i64* %13, align 8, !noalias !0
  %15 = add i64 %sp_13, 16
  %16 = inttoptr i64 %15 to i64*
  %17 = load i64, i64* %16, align 8, !noalias !0
  store i64 %17, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %14, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %12, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  ret { i64 } { i64 1 }

"0x8fc.exit":                                     ; preds = %"0x8c0"
  %18 = load i64, i64* %1, align 8, !noalias !0
  store i64 %18, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %19 = insertvalue { i64 } undef, i64 %6, 0
  ret { i64 } %19
}

; Function Attrs: noinline
define { i64, i64, i64 } @frame_dummy() local_unnamed_addr #0 {
"0x908":
  %x29_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %lr_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 30), align 8, !alias.scope !0
  %sp_3 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_3, -16
  %1 = inttoptr i64 %0 to i64*
  store i64 %x29_1, i64* %1, align 8, !noalias !0
  %2 = add i64 %sp_3, -8
  %3 = inttoptr i64 %2 to i64*
  store i64 %lr_2, i64* %3, align 8, !noalias !0
  %4 = load i64, i64* bitcast (%struct.__jove__jcr* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 28) to i64*), align 16, !noalias !0
  %5 = icmp eq i64 %4, 0
  %brmerge = or i1 %5, icmp eq (void ()* @_Jv_RegisterClasses, void ()* null)
  br i1 %brmerge, label %"0x920", label %"0x934.exit"

"0x920":                                          ; preds = %"0x934.exit", %"0x908"
  %6 = load i64, i64* %1, align 8, !noalias !0
  store i64 %6, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %sp_3, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  ret { i64, i64, i64 } { i64 ptrtoint (%struct.__jove__fini_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 29) to i64), i64 0, i64 0 }

"0x934.exit":                                     ; preds = %"0x908"
  tail call void @__jove_indirect_call(void ()* @_Jv_RegisterClasses)
  br label %"0x920"
}

; Function Attrs: noinline
define { i64, i64 } @main(i64 %x0, i64 %x1) local_unnamed_addr #0 {
"0x6c8":
  %x19_1 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %x20_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  %x21_3 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  %x22_4 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  %x29_5 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  %lr_6 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 30), align 8, !alias.scope !0
  %sp_7 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_7, -48
  %1 = inttoptr i64 %0 to i64*
  store i64 %x29_5, i64* %1, align 8, !noalias !0
  %2 = add i64 %sp_7, -40
  %3 = inttoptr i64 %2 to i64*
  store i64 %lr_6, i64* %3, align 8, !noalias !0
  %4 = trunc i64 %x0 to i32
  %5 = add i32 %4, -6
  %6 = icmp ugt i32 %4, 5
  %7 = zext i1 %6 to i32
  %8 = xor i32 %5, %4
  %9 = xor i32 %4, 6
  %10 = and i32 %8, %9
  %11 = add i64 %sp_7, -32
  %12 = inttoptr i64 %11 to i64*
  store i64 %x19_1, i64* %12, align 8, !noalias !0
  %13 = add i64 %sp_7, -24
  %14 = inttoptr i64 %13 to i64*
  store i64 %x20_2, i64* %14, align 8, !noalias !0
  %15 = add i64 %sp_7, -16
  %16 = inttoptr i64 %15 to i64*
  store i64 %x21_3, i64* %16, align 8, !noalias !0
  %17 = add i64 %sp_7, -8
  %18 = inttoptr i64 %17 to i64*
  store i64 %x22_4, i64* %18, align 8, !noalias !0
  %not.44 = icmp eq i32 %5, 0
  br i1 %not.44, label %"0x704.exit", label %"0x6e4.exit"

"0x6e4.exit":                                     ; preds = %"0x6c8"
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 20, i32 0, i64 16) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 %x1, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  tail call void @"0x698"()
  %sp_10 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %19 = add i64 %sp_10, 32
  %20 = add i64 %sp_10, 16
  %21 = add i64 %sp_10, 48
  %22 = inttoptr i64 %sp_10 to i64*
  %23 = load i64, i64* %22, align 8, !noalias !0
  %24 = add i64 %sp_10, 40
  %25 = inttoptr i64 %24 to i64*
  %26 = load i64, i64* %25, align 8, !noalias !0
  %27 = inttoptr i64 %19 to i64*
  %28 = load i64, i64* %27, align 8, !noalias !0
  %29 = add i64 %sp_10, 24
  %30 = inttoptr i64 %29 to i64*
  %31 = load i64, i64* %30, align 8, !noalias !0
  %32 = inttoptr i64 %20 to i64*
  %33 = load i64, i64* %32, align 8, !noalias !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  store i64 %33, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %31, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  store i64 %28, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  store i64 %26, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  store i64 %23, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %21, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  ret { i64, i64 } { i64 0, i64 undef }

"0x704.exit":                                     ; preds = %"0x6c8"
  %34 = add i64 %x1, 8
  %35 = inttoptr i64 %34 to i64*
  %36 = load i64, i64* %35, align 8, !noalias !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  store i64 %36, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  store i64 10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 2), align 8, !alias.scope !0
  store i64 %x1, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  tail call void @"0x6a8"()
  %x0_15 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  %x19_16 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %37 = add i64 %x19_16, 16
  %38 = inttoptr i64 %37 to i64*
  %39 = load i64, i64* %38, align 8, !noalias !0
  store i64 %39, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  store i64 10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 2), align 8, !alias.scope !0
  store i64 %x0_15, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  tail call void @"0x6a8"()
  %x0_20 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  %x19_21 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %40 = add i64 %x19_21, 32
  %41 = inttoptr i64 %40 to i64*
  %42 = load i64, i64* %41, align 8, !noalias !0
  store i64 %42, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  store i64 10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 2), align 8, !alias.scope !0
  store i64 %x0_20, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  tail call void @"0x6a8"()
  %x0_25 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  %x19_26 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %43 = add i64 %x19_26, 40
  %44 = inttoptr i64 %43 to i64*
  %45 = load i64, i64* %44, align 8, !noalias !0
  store i64 %45, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 0), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  store i64 10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 2), align 8, !alias.scope !0
  store i64 %x0_25, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  tail call void @"0x6a8"()
  %sp_31 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %x19_30 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  %46 = add i64 %x19_30, 24
  %47 = inttoptr i64 %46 to i64**
  %48 = load i64*, i64** %47, align 8, !noalias !0
  %49 = load i64, i64* %48, align 8, !noalias !0
  %50 = add i64 %49, 4294967254
  %51 = and i64 %50, 4294967295
  %52 = trunc i64 %50 to i32
  %53 = add i32 %52, -5
  %54 = icmp ugt i32 %52, 4
  %55 = zext i1 %54 to i32
  %56 = xor i32 %53, %52
  %57 = xor i32 %52, 5
  %58 = and i32 %56, %57
  %59 = icmp eq i32 %53, 0
  %not. = xor i1 %54, true
  %60 = or i1 %59, %not.
  br i1 %60, label %"0x76c", label %l138

"0x76c":                                          ; preds = %"0x704.exit"
  %61 = add i64 %51, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 20, i32 0, i64 4) to i64)
  %62 = inttoptr i64 %61 to i64*
  %63 = load i64, i64* %62, align 8, !noalias !0
  %sext = shl i64 %63, 56
  %64 = ashr exact i64 %sext, 54
  %65 = add i64 %64, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 188) to i64)
  store i32 %55, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %53, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %58, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %53, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  store i64 %65, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 1), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 17, i32 0, i64 188) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 2), align 8, !alias.scope !0
  store i64 %51, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 4), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 20, i32 0, i64 4) to i64), i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 5), align 8, !alias.scope !0
  %66 = inttoptr i64 %65 to void ()*
  tail call void @__jove_indirect_jump(void ()* %66)
  ret { i64, i64 } undef

l138:                                             ; preds = %"0x704.exit"
  %67 = add i64 %sp_31, 32
  %68 = add i64 %sp_31, 16
  %69 = add i64 %sp_31, 48
  %70 = inttoptr i64 %sp_31 to i64*
  %71 = load i64, i64* %70, align 8, !noalias !0
  %72 = add i64 %sp_31, 40
  %73 = inttoptr i64 %72 to i64*
  %74 = load i64, i64* %73, align 8, !noalias !0
  %75 = inttoptr i64 %67 to i64*
  %76 = load i64, i64* %75, align 8, !noalias !0
  %77 = add i64 %sp_31, 24
  %78 = inttoptr i64 %77 to i64*
  %79 = load i64, i64* %78, align 8, !noalias !0
  %80 = inttoptr i64 %68 to i64*
  %81 = load i64, i64* %80, align 8, !noalias !0
  store i32 %55, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %53, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %58, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %53, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  store i64 %81, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 19), align 8, !alias.scope !0
  store i64 %79, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 20), align 8, !alias.scope !0
  store i64 %76, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 21), align 8, !alias.scope !0
  store i64 %74, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 22), align 8, !alias.scope !0
  store i64 %71, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 29), align 8, !alias.scope !0
  store i64 %69, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %82 = insertvalue { i64, i64 } { i64 1, i64 undef }, i64 %51, 1
  ret { i64, i64 } %82
}

; Function Attrs: noinline norecurse nounwind readnone
define void @__libc_csu_fini() local_unnamed_addr #1 {
"0xa40":
  ret void
}

declare void @__jove_indirect_jump(void ()*) local_unnamed_addr

; Function Attrs: norecurse nounwind readnone uwtable
declare i64 @helper_sdiv64(i64, i64) local_unnamed_addr #3

declare void @__jove_indirect_call(void ()*) local_unnamed_addr

declare void @__jove_call(void ()*)

attributes #0 = { noinline }
attributes #1 = { noinline norecurse nounwind readnone }
attributes #2 = { noinline norecurse nounwind }
attributes #3 = { norecurse nounwind readnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!0 = !{!1}
!1 = !{!"JoveScope", !2}
!2 = !{!"JoveDomain"}
```
### x86_64
#### Machine Code
```asm
00000000000007c0 <cn_add>:
 7c0:   48 01 ce                add    %rcx,%rsi
 7c3:   48 8d 04 17             lea    (%rdi,%rdx,1),%rax
 7c7:   48 89 f2                mov    %rsi,%rdx
 7ca:   c3                      retq
 7cb:   0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

00000000000007d0 <cn_sub>:
 7d0:   48 29 ce                sub    %rcx,%rsi
 7d3:   48 89 f8                mov    %rdi,%rax
 7d6:   48 29 d0                sub    %rdx,%rax
 7d9:   48 89 f2                mov    %rsi,%rdx
 7dc:   c3                      retq
 7dd:   0f 1f 00                nopl   (%rax)

00000000000007e0 <cn_mul>:
 7e0:   48 89 f8                mov    %rdi,%rax
 7e3:   49 89 f0                mov    %rsi,%r8
 7e6:   48 0f af c2             imul   %rdx,%rax
 7ea:   4c 0f af c1             imul   %rcx,%r8
 7ee:   48 0f af f2             imul   %rdx,%rsi
 7f2:   4c 29 c0                sub    %r8,%rax
 7f5:   48 0f af f9             imul   %rcx,%rdi
 7f9:   48 8d 14 3e             lea    (%rsi,%rdi,1),%rdx
 7fd:   c3                      retq
 7fe:   66 90                   xchg   %ax,%ax

0000000000000800 <cn_div>:
 800:   49 89 d1                mov    %rdx,%r9
 803:   48 89 c8                mov    %rcx,%rax
 806:   49 89 d2                mov    %rdx,%r10
 809:   4c 0f af ca             imul   %rdx,%r9
 80d:   48 0f af c1             imul   %rcx,%rax
 811:   49 01 c1                add    %rax,%r9
 814:   48 89 f8                mov    %rdi,%rax
 817:   48 0f af c2             imul   %rdx,%rax
 81b:   48 89 f2                mov    %rsi,%rdx
 81e:   48 0f af d1             imul   %rcx,%rdx
 822:   49 0f af f2             imul   %r10,%rsi
 826:   48 01 d0                add    %rdx,%rax
 829:   48 99                   cqto
 82b:   49 f7 f9                idiv   %r9
 82e:   48 0f af f9             imul   %rcx,%rdi
 832:   49 89 c0                mov    %rax,%r8
 835:   48 29 fe                sub    %rdi,%rsi
 838:   48 89 f0                mov    %rsi,%rax
 83b:   48 99                   cqto
 83d:   49 f7 f9                idiv   %r9
 840:   48 89 c6                mov    %rax,%rsi
 843:   4c 89 c0                mov    %r8,%rax
 846:   48 89 f2                mov    %rsi,%rdx
 849:   c3                      retq
 84a:   66 0f 1f 44 00 00       nopw   0x0(%rax,%rax,1)
```
#### Running Jove
```bash
$ # $PWD is $JOVE_SRC_DIR/bin/x86_64
$ ./jove-init ../../tests/bin/gcc/debian-jessie/aarch64/complex-num
File: ../../tests/bin/gcc/debian-jessie/x86_64/complex-num
Format: ELF64-x86-64
Arch: x86_64
AddressSize: 64bit
MC TheTriple: x86_64-unknown-unknown-elf
MC TheTarget: 64-bit X86: EM64T and AMD64

Address Space:
.interp              [238, 254)
.note.ABI-tag        [254, 274)
.note.gnu.build-id   [274, 298)
.gnu.hash            [298, 2b4)
.dynsym              [2b8, 390)
.dynstr              [390, 41e)
.gnu.version         [41e, 430)
.gnu.version_r       [430, 450)
.rela.dyn            [450, 510)
.rela.plt            [510, 558)
.init                [558, 56f)
.plt                 [570, 5b0)
.plt.got             [5b0, 5b8)
.text                [5c0, 8c2)
.fini                [8c4, 8cd)
.rodata              [8d0, 90c)
.eh_frame_hdr        [90c, 968)
.eh_frame            [968, af4)
.init_array          [200de8, 200df0)
.fini_array          [200df0, 200df8)
.dynamic             [200df8, 200fd8)
.got                 [200fd8, 201000)
.got.plt             [201000, 201030)
.data                [201030, 201040)
.bss                 [201040, 201048)

Relocations:

  RELATIVE     @ 200de8           +7b0             
  RELATIVE     @ 200df0           +770             
  RELATIVE     @ 201038           +201038          
  ADDRESSOF    @ 200fd8           +0               _ITM_deregisterTMCloneTable    *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 200fe0           +0               __libc_start_main              *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 200fe8           +0               __gmon_start__                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 200ff0           +0               _ITM_registerTMCloneTable      *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 200ff8           +0               __cxa_finalize                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 201018           +0               puts                           *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 201020           +0               printf                         *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 201028           +0               atol                           *FUNCTION   *GLOBAL   @ 0 {0}

Exported Functions:

  _init                                    @ 558             
  main                                     @ 5c0             
  _start                                   @ 6b0             
  deregister_tm_clones                     @ 6e0             
  register_tm_clones                       @ 720             
  __do_global_dtors_aux                    @ 770             
  frame_dummy                              @ 7b0             
  cn_add                                   @ 7c0             
  cn_sub                                   @ 7d0             
  cn_mul                                   @ 7e0             
  cn_div                                   @ 800             
  __libc_csu_init                          @ 850             
  __libc_csu_fini                          @ 8c0             
  _fini                                    @ 8c4             

Translating x86_64 machine code to QEMU IR...

7e0
  7e0
    note: return
5c0
  5c0
    note: conditional jump to 5cf and 5e8
  5cf
    note: direct call to 580
  5db
    note: return
  5e8
    note: direct call to 5a0
  5f6
    note: direct call to 5a0
  604
    note: direct call to 5a0
  612
    note: direct call to 5a0
  620
    note: conditional jump to 62e and 672
  62e
    note: conditional jump to 630 and 65b
  630
    note: conditional jump to 634 and 68f
  634
    note: conditional jump to 638 and 685
  638
    note: direct call to 800
  646
    note: direct call to 590
  657
    note: unconditional jump to 5dd
  5dd
    note: return
  685
    note: unconditional jump to 5dd
  68f
    note: direct call to 7d0
  69d
    note: unconditional jump to 649
  649
    note: direct call to 590
  65b
    note: conditional jump to 65f and 685
  65f
    note: direct call to 7e0
  66d
    note: unconditional jump to 649
  672
    note: direct call to 7c0
  680
    note: unconditional jump to 649
7c0
  7c0
    note: return
6b0
  6b0
    note: indirect call
  6da
    note: unconditional jump to 6da
850
  850
    note: direct call to 558
  881
    note: conditional jump to 886 and 8a6
  886
    note: indirect call
  89d
    note: conditional jump to 8a6 and 890
  8a6
    note: return
  890
    note: indirect call
558
  558
    note: conditional jump to 568 and 56a
  568
    note: indirect call
  56a
    note: return
800
  800
    note: return
7d0
  7d0
    note: return
720
  720
    note: conditional jump to 748 and 760
  748
    note: conditional jump to 754 and 760
  754
    note: indirect jump
  760
    note: return
6e0
  6e0
    note: conditional jump to 6f7 and 710
  6f7
    note: conditional jump to 703 and 710
  703
    note: indirect jump
  710
    note: return
8c4
  8c4
    note: return
770
  770
    note: conditional jump to 779 and 7a8
  779
    note: conditional jump to 787 and 793
  787
    note: direct call to 5b0
  793
    note: direct call to 6e0
  798
    note: return
  7a8
    note: return
8c0
  8c0
    note: return
7b0
  7b0
    note: unconditional jump to 720
  720
    note: conditional jump to 748 and 760
  748
    note: conditional jump to 754 and 760
  754
    note: indirect jump
  760
    note: return
580
  580
    note: indirect jump
5a0
  5a0
    note: indirect jump
590
  590
    note: indirect jump
5b0
  5b0
    note: indirect jump

Translating QEMU IR to LLVM...

6b0
  6b0
    note: PC-relative expression @ 6bf
    note: PC-relative expression @ 6c6
    note: PC-relative expression @ 6cd
    note: PC-relative expression @ 6d4
  6da
    warning: unreachable code @ 6da
7c0
  7c0
5a0
  5a0
    note: PC-relative expression @ 5a0
558
  558
    note: PC-relative expression @ 55c
  568
  56a
5b0
  5b0
    note: PC-relative expression @ 5b0
800
  800
850
  850
    note: PC-relative expression @ 85b
    note: PC-relative expression @ 863
  881
  886
  89d
  8a6
  890
590
  590
    note: PC-relative expression @ 590
7e0
  7e0
5c0
  5c0
  5cf
    note: PC-relative expression @ 5cf
  5db
  5e8
  5f6
  604
  612
  620
  62e
  630
  634
  638
  646
    note: PC-relative expression @ 649
  657
  5dd
  685
  68f
  69d
  649
    note: PC-relative expression @ 649
  65b
  65f
  66d
  672
  680
720
  720
    note: PC-relative expression @ 720
    note: PC-relative expression @ 727
  748
    note: PC-relative expression @ 748
  754
  760
6e0
  6e0
    note: PC-relative expression @ 6e0
    note: PC-relative expression @ 6e8
  6f7
    note: PC-relative expression @ 6f7
  703
  710
8c4
  8c4
770
  770
    note: PC-relative expression @ 770
  779
    note: PC-relative expression @ 779
  787
    note: PC-relative expression @ 787
  793
  798
    note: PC-relative expression @ 798
  7a8
8c0
  8c0
7b0
  7b0
  720
    note: PC-relative expression @ 720
    note: PC-relative expression @ 727
  748
    note: PC-relative expression @ 748
  754
  760
7d0
  7d0
580
  580
    note: PC-relative expression @ 580
```
#### LLVM
```llvm
%struct.CPUX86State = type { [16 x i64], i64, i64, i64, i64, i64, i32, i32, i32, i32, [6 x %struct.SegmentCache], %struct.SegmentCache, %struct.SegmentCache, %struct.SegmentCache, %struct.SegmentCache, [5 x i64], i32, [4 x %struct.Int128], %struct.Int128, i64, i64, %struct.anon.13, i32, i16, i16, [8 x i8], [8 x i8], [8 x %union.FPReg], i16, i64, i64, %struct.float_status, %struct.floatx80, %struct.float_status, %struct.float_status, i32, [32 x %union.ZMMReg], %union.ZMMReg, %union.MMXReg, [8 x i64], i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, [3 x i64], [18 x i64], [18 x i64], i64, i32, %struct.anon.13, i64, i64, i64, i64, i64, i64, i64, i64, i64, [5 x i64], i64, i64, i64, i64, i64, [16 x i64], [4 x i64], [4 x i64], i32, i32, i64, [8 x i64], %union.anon.15, i32, i64, i64, i64, i16, i16, i16, i16, i32, i8, i8, i8, i32, i32, i32, i32, i32, i32, i32, [12 x i32], [12 x i32], [11 x i64], i64, [8 x %struct.Int128], i32, i32, i32, i8, i8, i32, i8, i64, i64, i8*, i64, i64, [40 x i64], i64, i16, i16, i16, i64, i64, i64, i32, i32, [8 x i8] }
%struct.SegmentCache = type { i32, i64, i32, i32 }
%struct.Int128 = type { i64, i64 }
%union.FPReg = type { %struct.floatx80 }
%struct.floatx80 = type { i64, i16 }
%struct.float_status = type { i8, i8, i8, i8, i8, i8, i8 }
%union.ZMMReg = type { [8 x i64] }
%union.MMXReg = type { [1 x i64] }
%struct.anon.13 = type {}
%union.anon.15 = type { [4 x %struct.CPUBreakpoint*] }
%struct.CPUBreakpoint = type { i64, i32, %struct.anon.18 }
%struct.anon.18 = type { %struct.CPUBreakpoint*, %struct.CPUBreakpoint** }
%struct.__jove_sections = type <{ %struct.__jove__interp, %struct.__jove__note_ABI-tag, %struct.__jove__note_gnu_build-id, %struct.__jove__gnu_hash, [4 x i8], %struct.__jove__dynsym, %struct.__jove__dynstr, %struct.__jove__gnu_version, %struct.__jove__gnu_version_r, %struct.__jove__rela_dyn, %struct.__jove__rela_plt, %struct.__jove__init, [1 x i8], %struct.__jove__plt, %struct.__jove__plt_got, [8 x i8], %struct.__jove__text, [2 x i8], %struct.__jove__fini, [3 x i8], %struct.__jove__rodata, %struct.__jove__eh_frame_hdr, %struct.__jove__eh_frame, [2097908 x i8], %struct.__jove__init_array, %struct.__jove__fini_array, %struct.__jove__dynamic, %struct.__jove__got, %struct.__jove__got_plt, %struct.__jove__data, %struct.__jove__bss }>
%struct.__jove__interp = type <{ [28 x i8] }>
%struct.__jove__note_ABI-tag = type <{ [32 x i8] }>
%struct.__jove__note_gnu_build-id = type <{ [36 x i8] }>
%struct.__jove__gnu_hash = type <{ [28 x i8] }>
%struct.__jove__dynsym = type <{ [216 x i8] }>
%struct.__jove__dynstr = type <{ [142 x i8] }>
%struct.__jove__gnu_version = type <{ [18 x i8] }>
%struct.__jove__gnu_version_r = type <{ [32 x i8] }>
%struct.__jove__rela_dyn = type <{ [192 x i8] }>
%struct.__jove__rela_plt = type <{ [72 x i8] }>
%struct.__jove__init = type <{ [23 x i8] }>
%struct.__jove__plt = type <{ [64 x i8] }>
%struct.__jove__plt_got = type <{ [8 x i8] }>
%struct.__jove__text = type <{ [770 x i8] }>
%struct.__jove__fini = type <{ [9 x i8] }>
%struct.__jove__rodata = type <{ [60 x i8] }>
%struct.__jove__eh_frame_hdr = type <{ [92 x i8] }>
%struct.__jove__eh_frame = type <{ [396 x i8] }>
%struct.__jove__init_array = type <{ i64* }>
%struct.__jove__fini_array = type <{ i64* }>
%struct.__jove__dynamic = type <{ [480 x i8] }>
%struct.__jove__got = type <{ void ()*, void ()*, void ()*, void ()*, void ()* }>
%struct.__jove__got_plt = type <{ [24 x i8], void ()*, void ()*, void ()* }>
%struct.__jove__data = type <{ [8 x i8], i64* }>
%struct.__jove__bss = type <{ [8 x i8] }>

@cpu_state = external thread_local local_unnamed_addr global %struct.CPUX86State
@__jove_sections = global %struct.__jove_sections <{ %struct.__jove__interp <{ [28 x i8] c"/lib64/ld-linux-x86-64.so.2\00" }>, %struct.__jove__note_ABI-tag <{ [32 x i8] c"\04\00\00\00\10\00\00\00\01\00\00\00GNU\00\00\00\00\00\02\00\00\00\06\00\00\00 \00\00\00" }>, %struct.__jove__note_gnu_build-id <{ [36 x i8] c"\04\00\00\00\14\00\00\00\03\00\00\00GNU\00\E3\12\9D\08\D1\DBQw\19\C1<'H\22\09Xw<\0B\A1" }>, %struct.__jove__gnu_hash <{ [28 x i8] c"\01\00\00\00\01\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, [4 x i8] zeroinitializer, %struct.__jove__dynsym <{ [216 x i8] c"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00=\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0B\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\10\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00+\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00Y\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\17\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00h\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\1C\00\00\00\22\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__dynstr <{ [142 x i8] c"\00libc.so.6\00puts\00printf\00atol\00__cxa_finalize\00__libc_start_main\00_ITM_deregisterTMCloneTable\00__gmon_start__\00_ITM_registerTMCloneTable\00GLIBC_2.2.5\00" }>, %struct.__jove__gnu_version <{ [18 x i8] c"\00\00\00\00\02\00\02\00\02\00\00\00\02\00\00\00\02\00" }>, %struct.__jove__gnu_version_r <{ [32 x i8] c"\01\00\01\00\01\00\00\00\10\00\00\00\00\00\00\00u\1Ai\09\00\00\02\00\82\00\00\00\00\00\00\00" }>, %struct.__jove__rela_dyn <{ [192 x i8] c"\E8\0D \00\00\00\00\00\08\00\00\00\00\00\00\00\B0\07\00\00\00\00\00\00\F0\0D \00\00\00\00\00\08\00\00\00\00\00\00\00p\07\00\00\00\00\00\008\10 \00\00\00\00\00\08\00\00\00\00\00\00\008\10 \00\00\00\00\00\D8\0F \00\00\00\00\00\06\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\E0\0F \00\00\00\00\00\06\00\00\00\04\00\00\00\00\00\00\00\00\00\00\00\E8\0F \00\00\00\00\00\06\00\00\00\05\00\00\00\00\00\00\00\00\00\00\00\F0\0F \00\00\00\00\00\06\00\00\00\07\00\00\00\00\00\00\00\00\00\00\00\F8\0F \00\00\00\00\00\06\00\00\00\08\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__rela_plt <{ [72 x i8] c"\18\10 \00\00\00\00\00\07\00\00\00\02\00\00\00\00\00\00\00\00\00\00\00 \10 \00\00\00\00\00\07\00\00\00\03\00\00\00\00\00\00\00\00\00\00\00(\10 \00\00\00\00\00\07\00\00\00\06\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__init <{ [23 x i8] c"H\83\EC\08H\8B\05\85\0A \00H\85\C0t\02\FF\D0H\83\C4\08\C3" }>, [1 x i8] zeroinitializer, %struct.__jove__plt <{ [64 x i8] c"\FF5\92\0A \00\FF%\94\0A \00\0F\1F@\00\FF%\92\0A \00h\00\00\00\00\E9\E0\FF\FF\FF\FF%\8A\0A \00h\01\00\00\00\E9\D0\FF\FF\FF\FF%\82\0A \00h\02\00\00\00\E9\C0\FF\FF\FF" }>, %struct.__jove__plt_got <{ [8 x i8] c"\FF%B\0A \00f\90" }>, [8 x i8] zeroinitializer, %struct.__jove__text <{ [770 x i8] c"AUATUSH\83\EC\08\83\FF\06t\19H\8D=\02\03\00\00\E8\A5\FF\FF\FF1\C0H\83\C4\08[]A\5CA]\C3H\8B~\08H\89\F31\C0\E8\AA\FF\FF\FFH\8B{\10Lc\E01\C0\E8\9C\FF\FF\FFH\8B{ Hc\E81\C0\E8\8E\FF\FF\FFH\8B{(Lc\E81\C0\E8\80\FF\FF\FFHc\C8H\8BC\18\0F\B6\00<+tD~+<-t[</uMH\89\EEL\89\EAL\89\E7\E8\BA\01\00\00H\89\C6H\8D=\B0\02\00\001\C0\E89\FF\FF\FF1\C0\EB\82<*u&H\89\EEL\89\EAL\89\E7\E8s\01\00\00H\89\C6\EB\D7H\89\EEL\89\EAL\89\E7\E8@\01\00\00H\89\C6\EB\C4\B8\01\00\00\00\E9N\FF\FF\FFH\89\EEL\89\EAL\89\E7\E83\01\00\00H\89\C6\EB\A7f.\0F\1F\84\00\00\00\00\00\0F\1F@\001\EDI\89\D1^H\89\E2H\83\E4\F0PTL\8D\05\FA\01\00\00H\8D\0D\83\01\00\00H\8D=\EC\FE\FF\FF\FF\15\06\09 \00\F4\0F\1FD\00\00H\8D=Y\09 \00UH\8D\05Q\09 \00H9\F8H\89\E5t\19H\8B\05\DA\08 \00H\85\C0t\0D]\FF\E0f.\0F\1F\84\00\00\00\00\00]\C3\0F\1F@\00f.\0F\1F\84\00\00\00\00\00H\8D=\19\09 \00H\8D5\12\09 \00UH)\FEH\89\E5H\C1\FE\03H\89\F0H\C1\E8?H\01\C6H\D1\FEt\18H\8B\05\A1\08 \00H\85\C0t\0C]\FF\E0f\0F\1F\84\00\00\00\00\00]\C3\0F\1F@\00f.\0F\1F\84\00\00\00\00\00\80=\C9\08 \00\00u/H\83=w\08 \00\00UH\89\E5t\0CH\8B=\AA\08 \00\E8\1D\FE\FF\FF\E8H\FF\FF\FF\C6\05\A1\08 \00\01]\C3\0F\1F\80\00\00\00\00\F3\C3f\0F\1FD\00\00UH\89\E5]\E9f\FF\FF\FFf\0F\1FD\00\00H\01\CEH\8D\04\17H\89\F2\C3\0F\1FD\00\00H)\CEH\89\F8H)\D0H\89\F2\C3\0F\1F\00H\89\F8I\89\F0H\0F\AF\C2L\0F\AF\C1H\0F\AF\F2L)\C0H\0F\AF\F9H\8D\14>\C3f\90I\89\D1H\89\C8I\89\D2L\0F\AF\CAH\0F\AF\C1I\01\C1H\89\F8H\0F\AF\C2H\89\F2H\0F\AF\D1I\0F\AF\F2H\01\D0H\99I\F7\F9H\0F\AF\F9I\89\C0H)\FEH\89\F0H\99I\F7\F9H\89\C6L\89\C0H\89\F2\C3f\0F\1FD\00\00AWAVI\89\D7AUATL\8D%\86\05 \00UH\8D-\86\05 \00SA\89\FDI\89\F6L)\E5H\83\EC\08H\C1\FD\03\E8\D7\FC\FF\FFH\85\EDt 1\DB\0F\1F\84\00\00\00\00\00L\89\FAL\89\F6D\89\EFA\FF\14\DCH\83\C3\01H9\DDu\EAH\83\C4\08[]A\5CA]A^A_\C3\90f.\0F\1F\84\00\00\00\00\00\F3\C3" }>, [2 x i8] zeroinitializer, %struct.__jove__fini <{ [9 x i8] c"H\83\EC\08H\83\C4\08\C3" }>, [3 x i8] zeroinitializer, %struct.__jove__rodata <{ [60 x i8] c"\01\00\02\00\00\00\00\00usage: complex-num w x [+-*/] y z\00\00\00\00\00\00\00%li + %lii\0A\00" }>, %struct.__jove__eh_frame_hdr <{ [92 x i8] c"\01\1B\03;X\00\00\00\0A\00\00\00d\FC\FF\FF\A4\00\00\00\A4\FC\FF\FF\CC\00\00\00\B4\FC\FF\FFD\01\00\00\A4\FD\FF\FFt\00\00\00\B4\FE\FF\FF\E4\00\00\00\C4\FE\FF\FF\FC\00\00\00\D4\FE\FF\FF\14\01\00\00\F4\FE\FF\FF,\01\00\00D\FF\FF\FF\84\01\00\00\B4\FF\FF\FF\CC\01\00\00" }>, %struct.__jove__eh_frame <{ [396 x i8] c"\14\00\00\00\00\00\00\00\01zR\00\01x\10\01\1B\0C\07\08\90\01\07\10\14\00\00\00\1C\00\00\00(\FD\FF\FF+\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\00\00\00\00\01zR\00\01x\10\01\1B\0C\07\08\90\01\00\00$\00\00\00\1C\00\00\00\B8\FB\FF\FF@\00\00\00\00\0E\10F\0E\18J\0F\0Bw\08\80\00?\1A;*3$\22\00\00\00\00\14\00\00\00D\00\00\00\D0\FB\FF\FF\08\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\5C\00\00\00\C8\FD\FF\FF\0B\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00t\00\00\00\C0\FD\FF\FF\0D\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\8C\00\00\00\B8\FD\FF\FF\1E\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\A4\00\00\00\C0\FD\FF\FFJ\00\00\00\00\00\00\00\00\00\00\00<\00\00\00\BC\00\00\00h\FB\FF\FF\E2\00\00\00\00B\0E\10\8D\02B\0E\18\8C\03A\0E \86\04A\0E(\83\05D\0E0W\0A\0E(A\0E A\0E\18B\0E\10B\0E\08A\0B\00\00\00\00\00\00D\00\00\00\FC\00\00\00\B8\FD\FF\FFe\00\00\00\00B\0E\10\8F\02B\0E\18\8E\03E\0E \8D\04B\0E(\8C\05H\0E0\86\06H\0E8\83\07M\0E@r\0E8A\0E0A\0E(B\0E B\0E\18B\0E\10B\0E\08\00\14\00\00\00D\01\00\00\E0\FD\FF\FF\02\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, [2097908 x i8] zeroinitializer, %struct.__jove__init_array <{ i64* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 16, i32 0, i64 496) to i64*) }>, %struct.__jove__fini_array <{ i64* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 16, i32 0, i64 432) to i64*) }>, %struct.__jove__dynamic <{ [480 x i8] c"\01\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\0C\00\00\00\00\00\00\00X\05\00\00\00\00\00\00\0D\00\00\00\00\00\00\00\C4\08\00\00\00\00\00\00\19\00\00\00\00\00\00\00\E8\0D \00\00\00\00\00\1B\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\1A\00\00\00\00\00\00\00\F0\0D \00\00\00\00\00\1C\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\F5\FE\FFo\00\00\00\00\98\02\00\00\00\00\00\00\05\00\00\00\00\00\00\00\90\03\00\00\00\00\00\00\06\00\00\00\00\00\00\00\B8\02\00\00\00\00\00\00\0A\00\00\00\00\00\00\00\8E\00\00\00\00\00\00\00\0B\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\15\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\00\10 \00\00\00\00\00\02\00\00\00\00\00\00\00H\00\00\00\00\00\00\00\14\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00\17\00\00\00\00\00\00\00\10\05\00\00\00\00\00\00\07\00\00\00\00\00\00\00P\04\00\00\00\00\00\00\08\00\00\00\00\00\00\00\C0\00\00\00\00\00\00\00\09\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\FB\FF\FFo\00\00\00\00\00\00\00\08\00\00\00\00\FE\FF\FFo\00\00\00\000\04\00\00\00\00\00\00\FF\FF\FFo\00\00\00\00\01\00\00\00\00\00\00\00\F0\FF\FFo\00\00\00\00\1E\04\00\00\00\00\00\00\F9\FF\FFo\00\00\00\00\03\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__got <{ void ()* @_ITM_deregisterTMCloneTable, void ()* @__libc_start_main, void ()* @__gmon_start__, void ()* @_ITM_registerTMCloneTable, void ()* @__cxa_finalize }>, %struct.__jove__got_plt <{ [24 x i8] c"\F8\0D \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00", void ()* @puts, void ()* @printf, void ()* @atol }>, %struct.__jove__data <{ [8 x i8] zeroinitializer, i64* bitcast (i64** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 29, i32 1) to i64*) }>, %struct.__jove__bss <{ [8 x i8] c"GCC: (GN" }> }>, align 4096

declare extern_weak void @_ITM_deregisterTMCloneTable()

declare void @__libc_start_main()

declare extern_weak void @__gmon_start__()

declare extern_weak void @_ITM_registerTMCloneTable()

declare extern_weak void @__cxa_finalize()

declare void @puts()

declare void @printf()

declare void @atol()

; Function Attrs: noinline noreturn
define void @_start(i64 %rdx) local_unnamed_addr #0 {
"0x6b0":
  %rax_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %rsp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %0 = add i64 %rsp_2, 8
  %1 = and i64 %0, -16
  %2 = add i64 %1, -8
  %3 = inttoptr i64 %2 to i64*
  store i64 %rax_1, i64* %3, align 8, !noalias !0
  %4 = add i64 %1, -16
  %5 = inttoptr i64 %4 to i64*
  store i64 %2, i64* %5, align 16, !noalias !0
  %6 = add i64 %1, -24
  %7 = inttoptr i64 %6 to i64*
  store i64 1754, i64* %7, align 8, !noalias !0
  tail call void @__jove_indirect_call(void ()* nonnull @__libc_start_main)
  unreachable
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_add(i64 %rdi, i64 %rsi, i64 %rdx, i64 %rcx) local_unnamed_addr #1 {
"0x7c0":
  %0 = add i64 %rcx, %rsi
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %1 = add i64 %rsp_1, 8
  %2 = add i64 %rdx, %rdi
  store i32 9, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 %rcx, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %1, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  %3 = insertvalue { i64, i64 } undef, i64 %2, 0
  %4 = insertvalue { i64, i64 } %3, i64 %0, 1
  ret { i64, i64 } %4
}

; Function Attrs: noinline
define internal void @"0x5a0"() local_unnamed_addr #2 {
"0x5a0":
  tail call void @__jove_call(void ()* nonnull @atol)
  ret void
}

; Function Attrs: noinline
define { i64 } @_init() local_unnamed_addr #2 {
"0x558":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %0 = add i64 %rsp_1, -8
  br i1 icmp eq (void ()* @__gmon_start__, void ()* null), label %"0x56a.exit", label %"0x568"

"0x568":                                          ; preds = %"0x558"
  %1 = add i64 %rsp_1, -16
  %2 = inttoptr i64 %1 to i64*
  store i64 1386, i64* %2, align 8, !noalias !0
  tail call void @__jove_indirect_call(void ()* @__gmon_start__)
  br label %"0x56a.exit"

"0x56a.exit":                                     ; preds = %"0x568", %"0x558"
  %rsp_.0 = phi i64 [ %1, %"0x568" ], [ %0, %"0x558" ]
  %3 = add i64 %rsp_.0, 8
  %4 = add i64 %rsp_.0, 16
  store i32 9, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %3, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 8, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %4, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  ret { i64 } { i64 ptrtoint (void ()* @__gmon_start__ to i64) }
}

; Function Attrs: noinline
define internal void @"0x5b0"() local_unnamed_addr #2 {
"0x5b0":
  tail call void @__jove_call(void ()* @__cxa_finalize)
  ret void
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_div(i64 %rdi, i64 %rsi, i64 %rdx, i64 %rcx) local_unnamed_addr #1 {
"0x800":
  %0 = mul i64 %rdx, %rdx
  %1 = mul i64 %rcx, %rcx
  %2 = add i64 %1, %0
  %3 = mul i64 %rdx, %rdi
  %4 = mul i64 %rcx, %rsi
  %5 = mul i64 %rdx, %rsi
  %6 = add i64 %4, %3
  %7 = tail call { i64, i64 } @helper_idivq_EAX(i64 %2, i64 undef, i64 %rcx)
  %8 = extractvalue { i64, i64 } %7, 0
  %9 = extractvalue { i64, i64 } %7, 1
  %10 = mul i64 %9, %rdi
  %11 = sub i64 %5, %10
  %12 = tail call { i64, i64 } @helper_idivq_EAX(i64 %2, i64 %8, i64 %9)
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %13 = add i64 %rsp_1, 8
  %14 = extractvalue { i64, i64 } %12, 1
  %15 = extractvalue { i64, i64 } %12, 0
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %11, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %15, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 5), align 8, !alias.scope !0
  store i64 %14, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 1), align 8, !alias.scope !0
  store i64 %13, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %11, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  store i64 %6, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 9), align 8, !alias.scope !0
  store i64 %rdx, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 10), align 8, !alias.scope !0
  %16 = insertvalue { i64, i64 } undef, i64 %6, 0
  %17 = insertvalue { i64, i64 } %16, i64 %11, 1
  ret { i64, i64 } %17
}

; Function Attrs: noinline
define void @__libc_csu_init(i64 %rdi, i64 %rsi, i64 %rdx) local_unnamed_addr #2 {
"0x850":
  %rbx_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  %rsp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_3 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %r12_4 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  %r13_5 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  %r14_6 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %r15_7 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 15), align 8, !alias.scope !0
  %0 = add i64 %rsp_2, -8
  %1 = inttoptr i64 %0 to i64*
  store i64 %r15_7, i64* %1, align 8, !noalias !0
  %2 = add i64 %rsp_2, -16
  %3 = inttoptr i64 %2 to i64*
  store i64 %r14_6, i64* %3, align 8, !noalias !0
  %4 = add i64 %rsp_2, -24
  %5 = inttoptr i64 %4 to i64*
  store i64 %r13_5, i64* %5, align 8, !noalias !0
  %6 = add i64 %rsp_2, -32
  %7 = inttoptr i64 %6 to i64*
  store i64 %r12_4, i64* %7, align 8, !noalias !0
  %8 = add i64 %rsp_2, -40
  %9 = inttoptr i64 %8 to i64*
  store i64 %rbp_3, i64* %9, align 8, !noalias !0
  %10 = add i64 %rsp_2, -48
  %11 = inttoptr i64 %10 to i64*
  store i64 %rbx_1, i64* %11, align 8, !noalias !0
  %12 = add i64 %rsp_2, -64
  %13 = inttoptr i64 %12 to i64*
  store i64 2177, i64* %13, align 8, !noalias !0
  %14 = and i64 %rdi, 4294967295
  store i32 41, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 1, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %12, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 1, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  store i64 ptrtoint (%struct.__jove__init_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 24) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i64 %14, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  store i64 %rsi, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  store i64 %rdx, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 15), align 8, !alias.scope !0
  %15 = tail call { i64 } @_init()
  store i64 ptrtoint (void ()* @__gmon_start__ to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %rsp_8 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_9 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %r12_10 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  %not. = icmp eq i64 %rbp_9, 0
  br i1 %not., label %"0x8a6", label %"0x886"

"0x886":                                          ; preds = %"0x850"
  %16 = inttoptr i64 %r12_10 to void ()**
  %17 = load void ()*, void ()** %16, align 8, !noalias !0
  %18 = add i64 %rsp_8, -8
  %19 = inttoptr i64 %18 to i64*
  store i64 2205, i64* %19, align 8, !noalias !0
  tail call void @__jove_indirect_call(void ()* %17)
  %20 = icmp eq i64 %rbp_9, 1
  br i1 %20, label %"0x8a6", label %"0x890.preheader"

"0x890.preheader":                                ; preds = %"0x886"
  br label %"0x890"

"0x8a6.loopexit":                                 ; preds = %"0x890"
  %21 = shl i64 %rbp_9, 3
  %22 = sub i64 %rsp_8, %21
  br label %"0x8a6"

"0x8a6":                                          ; preds = %"0x8a6.loopexit", %"0x886", %"0x850"
  %rsp_.1 = phi i64 [ %rsp_8, %"0x850" ], [ %18, %"0x886" ], [ %22, %"0x8a6.loopexit" ]
  %23 = add i64 %rsp_.1, 8
  %24 = add i64 %rsp_.1, 48
  %25 = add i64 %rsp_.1, 40
  %26 = add i64 %rsp_.1, 32
  %27 = add i64 %rsp_.1, 24
  %28 = add i64 %rsp_.1, 16
  %29 = add i64 %rsp_.1, 64
  %30 = inttoptr i64 %24 to i64*
  %31 = load i64, i64* %30, align 8, !noalias !0
  %32 = inttoptr i64 %25 to i64*
  %33 = load i64, i64* %32, align 8, !noalias !0
  %34 = inttoptr i64 %26 to i64*
  %35 = load i64, i64* %34, align 8, !noalias !0
  %36 = inttoptr i64 %27 to i64*
  %37 = load i64, i64* %36, align 8, !noalias !0
  %38 = inttoptr i64 %28 to i64*
  %39 = load i64, i64* %38, align 8, !noalias !0
  %40 = inttoptr i64 %23 to i64*
  %41 = load i64, i64* %40, align 8, !noalias !0
  store i32 9, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %23, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 8, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %41, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  store i64 %29, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %39, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  store i64 %37, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i64 %35, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  store i64 %33, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  store i64 %31, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 15), align 8, !alias.scope !0
  ret void

"0x890":                                          ; preds = %"0x890", %"0x890.preheader"
  %42 = phi i64 [ %49, %"0x890" ], [ 1, %"0x890.preheader" ]
  %rsp_.043 = phi i64 [ %47, %"0x890" ], [ %18, %"0x890.preheader" ]
  %43 = shl i64 %42, 3
  %44 = add i64 %43, %r12_10
  %45 = inttoptr i64 %44 to void ()**
  %46 = load void ()*, void ()** %45, align 8, !noalias !0
  %47 = add i64 %rsp_.043, -8
  %48 = inttoptr i64 %47 to i64*
  store i64 2205, i64* %48, align 8, !noalias !0
  tail call void @__jove_indirect_call(void ()* %46)
  %49 = add i64 %42, 1
  %50 = icmp eq i64 %rbp_9, %49
  br i1 %50, label %"0x8a6.loopexit", label %"0x890"
}

; Function Attrs: noinline
define internal void @"0x590"() local_unnamed_addr #2 {
"0x590":
  tail call void @__jove_call(void ()* nonnull @printf)
  ret void
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_mul(i64 %rdi, i64 %rsi, i64 %rdx, i64 %rcx) local_unnamed_addr #1 {
"0x7e0":
  %0 = mul i64 %rcx, %rsi
  %1 = mul i64 %rdx, %rsi
  %2 = mul i64 %rcx, %rdi
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %3 = add i64 %rsp_1, 8
  %4 = add i64 %2, %1
  %5 = ashr i64 %2, 63
  %6 = tail call i64 @helper_mulsh_i64(i64 %rcx, i64 %rdi)
  %7 = sub i64 %5, %6
  %8 = mul i64 %rdx, %rdi
  %9 = sub i64 %8, %0
  store i32 5, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 %7, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %3, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %1, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  %10 = insertvalue { i64, i64 } undef, i64 %9, 0
  %11 = insertvalue { i64, i64 } %10, i64 %4, 1
  ret { i64, i64 } %11
}

; Function Attrs: noinline
define { i64 } @main(i64 %rdi, i64 %rsi) local_unnamed_addr #2 {
"0x5c0":
  %rbx_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  %rsp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_3 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %r12_4 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  %r13_5 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  %0 = add i64 %rsp_2, -8
  %1 = inttoptr i64 %0 to i64*
  store i64 %r13_5, i64* %1, align 8, !noalias !0
  %2 = add i64 %rsp_2, -16
  %3 = inttoptr i64 %2 to i64*
  store i64 %r12_4, i64* %3, align 8, !noalias !0
  %4 = add i64 %rsp_2, -24
  %5 = inttoptr i64 %4 to i64*
  store i64 %rbp_3, i64* %5, align 8, !noalias !0
  %6 = add i64 %rsp_2, -32
  %7 = inttoptr i64 %6 to i64*
  store i64 %rbx_1, i64* %7, align 8, !noalias !0
  %8 = add i64 %rdi, -6
  %9 = and i64 %8, 4294967295
  %not. = icmp eq i64 %9, 0
  br i1 %not., label %"0x5e8", label %"0x5cf"

"0x5cf":                                          ; preds = %"0x5c0"
  %10 = add i64 %rsp_2, -48
  %11 = inttoptr i64 %10 to i64*
  store i64 1499, i64* %11, align 8, !noalias !0
  store i32 16, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %8, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 6, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 20, i32 0, i64 8) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @puts)
  %rsp_11 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %12 = add i64 %rsp_11, 8
  %13 = add i64 %rsp_11, 32
  %14 = add i64 %rsp_11, 24
  %15 = add i64 %rsp_11, 16
  %16 = add i64 %rsp_11, 48
  %17 = inttoptr i64 %13 to i64*
  %18 = load i64, i64* %17, align 8, !noalias !0
  %19 = inttoptr i64 %14 to i64*
  %20 = load i64, i64* %19, align 8, !noalias !0
  %21 = inttoptr i64 %15 to i64*
  %22 = load i64, i64* %21, align 8, !noalias !0
  %23 = inttoptr i64 %12 to i64*
  %24 = load i64, i64* %23, align 8, !noalias !0
  store i32 9, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %12, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 8, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %24, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  store i64 %16, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %22, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  store i64 %20, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i64 %18, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  ret { i64 } zeroinitializer

"0x5e8":                                          ; preds = %"0x5c0"
  %25 = add i64 %rsi, 8
  %26 = inttoptr i64 %25 to i64*
  %27 = load i64, i64* %26, align 8, !noalias !0
  %28 = add i64 %rsp_2, -48
  %29 = inttoptr i64 %28 to i64*
  store i64 1526, i64* %29, align 8, !noalias !0
  store i32 49, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %rsi, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  store i64 %28, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %27, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @atol)
  %rsp_25 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbx_24 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  %rax_23 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %30 = add i64 %rbx_24, 16
  %31 = inttoptr i64 %30 to i64*
  %32 = load i64, i64* %31, align 8, !noalias !0
  %33 = add i64 %rsp_25, -8
  %34 = inttoptr i64 %33 to i64*
  store i64 1540, i64* %34, align 8, !noalias !0
  %sext = shl i64 %rax_23, 32
  %35 = ashr exact i64 %sext, 32
  store i32 49, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %33, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %32, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  store i64 %35, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @atol)
  %rsp_33 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbx_32 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  %rax_31 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %36 = add i64 %rbx_32, 32
  %37 = inttoptr i64 %36 to i64*
  %38 = load i64, i64* %37, align 8, !noalias !0
  %39 = add i64 %rsp_33, -8
  %40 = inttoptr i64 %39 to i64*
  store i64 1554, i64* %40, align 8, !noalias !0
  %sext165 = shl i64 %rax_31, 32
  %41 = ashr exact i64 %sext165, 32
  store i32 49, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %39, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %41, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  store i64 %38, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @atol)
  %rsp_42 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbx_41 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  %rax_40 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %42 = add i64 %rbx_41, 40
  %43 = inttoptr i64 %42 to i64*
  %44 = load i64, i64* %43, align 8, !noalias !0
  %45 = add i64 %rsp_42, -8
  %46 = inttoptr i64 %45 to i64*
  store i64 1568, i64* %46, align 8, !noalias !0
  %sext166 = shl i64 %rax_40, 32
  %47 = ashr exact i64 %sext166, 32
  store i32 49, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %45, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %44, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  store i64 %47, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @atol)
  %rsp_52 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_53 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %r12_54 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  %r13_55 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  %rbx_51 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  %rax_50 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %sext167 = shl i64 %rax_50, 32
  %48 = ashr exact i64 %sext167, 32
  %49 = add i64 %rbx_51, 24
  %50 = inttoptr i64 %49 to i64**
  %51 = load i64*, i64** %50, align 8, !noalias !0
  %52 = load i64, i64* %51, align 8, !noalias !0
  %53 = and i64 %52, 4294967295
  %54 = add nsw i64 %53, -43
  %fold = add i64 %52, 213
  %55 = and i64 %fold, 255
  %not.180 = icmp eq i64 %55, 0
  br i1 %not.180, label %"0x672", label %"0x62e"

"0x62e":                                          ; preds = %"0x5e8"
  %56 = tail call i64 @helper_cc_compute_all(i64 %54, i64 43, i64 undef, i32 14)
  %57 = lshr i64 %56, 4
  %58 = xor i64 %57, %56
  %59 = and i64 %58, 192
  %60 = icmp eq i64 %59, 0
  br i1 %60, label %"0x630", label %"0x65b"

"0x630":                                          ; preds = %"0x62e"
  %fold169 = add i64 %52, 211
  %61 = and i64 %fold169, 255
  %not.181 = icmp eq i64 %61, 0
  br i1 %not.181, label %"0x68f", label %"0x634"

"0x634":                                          ; preds = %"0x630"
  %fold170 = add i64 %52, 209
  %62 = and i64 %fold170, 255
  %63 = icmp eq i64 %62, 0
  br i1 %63, label %"0x638", label %"0x5dd"

"0x638":                                          ; preds = %"0x634"
  %64 = add nsw i64 %53, -47
  %65 = add i64 %rsp_52, -8
  %66 = inttoptr i64 %65 to i64*
  store i64 1606, i64* %66, align 8, !noalias !0
  store i32 14, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 47, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %53, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %65, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %67 = tail call { i64, i64 } @cn_div(i64 %r12_54, i64 %rbp_53, i64 %r13_55, i64 %48)
  %rax_returned = extractvalue { i64, i64 } %67, 0
  %rdx_returned = extractvalue { i64, i64 } %67, 1
  store i64 %rdx_returned, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  %rsp_88 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %68 = add i64 %rsp_88, -8
  %69 = inttoptr i64 %68 to i64*
  store i64 1623, i64* %69, align 8, !noalias !0
  store i32 49, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %68, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %rax_returned, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 20, i32 0, i64 48) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @printf)
  br label %"0x657.exit"

"0x657.exit":                                     ; preds = %"0x649", %"0x638"
  %rsp_.0 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  br label %"0x5dd"

"0x5dd":                                          ; preds = %"0x65b", %"0x657.exit", %"0x634"
  %rsp_.1 = phi i64 [ %rsp_.0, %"0x657.exit" ], [ %rsp_52, %"0x634" ], [ %rsp_52, %"0x65b" ]
  %rax_.0 = phi i64 [ 0, %"0x657.exit" ], [ 1, %"0x634" ], [ 1, %"0x65b" ]
  %70 = add i64 %rsp_.1, 8
  %71 = add i64 %rsp_.1, 32
  %72 = add i64 %rsp_.1, 24
  %73 = add i64 %rsp_.1, 16
  %74 = add i64 %rsp_.1, 48
  %75 = inttoptr i64 %71 to i64*
  %76 = load i64, i64* %75, align 8, !noalias !0
  %77 = inttoptr i64 %72 to i64*
  %78 = load i64, i64* %77, align 8, !noalias !0
  %79 = inttoptr i64 %73 to i64*
  %80 = load i64, i64* %79, align 8, !noalias !0
  %81 = inttoptr i64 %70 to i64*
  %82 = load i64, i64* %81, align 8, !noalias !0
  store i32 9, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %70, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 8, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %48, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 1), align 8, !alias.scope !0
  store i64 %82, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 3), align 8, !alias.scope !0
  store i64 %74, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %80, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  store i64 %78, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i64 %76, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 13), align 8, !alias.scope !0
  %83 = insertvalue { i64 } undef, i64 %rax_.0, 0
  ret { i64 } %83

"0x68f":                                          ; preds = %"0x630"
  %84 = add nsw i64 %53, -45
  %85 = add i64 %rsp_52, -8
  %86 = inttoptr i64 %85 to i64*
  store i64 1693, i64* %86, align 8, !noalias !0
  store i32 14, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %84, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 45, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %53, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %85, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %87 = tail call { i64, i64 } @cn_sub(i64 %r12_54, i64 %rbp_53, i64 %r13_55, i64 %48)
  br label %"0x649"

"0x649":                                          ; preds = %"0x672", %"0x65f", %"0x68f"
  %.sink179 = phi { i64, i64 } [ %98, %"0x672" ], [ %95, %"0x65f" ], [ %87, %"0x68f" ]
  %rax_returned159 = extractvalue { i64, i64 } %.sink179, 0
  %rdx_returned160 = extractvalue { i64, i64 } %.sink179, 1
  store i64 %rdx_returned160, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  %rsp_161 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %88 = add i64 %rsp_161, -8
  %89 = inttoptr i64 %88 to i64*
  store i64 1623, i64* %89, align 8, !noalias !0
  store i32 49, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %88, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %rax_returned159, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i64 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 20, i32 0, i64 48) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* nonnull @printf)
  br label %"0x657.exit"

"0x65b":                                          ; preds = %"0x62e"
  %fold168 = add i64 %52, 214
  %90 = and i64 %fold168, 255
  %91 = icmp eq i64 %90, 0
  br i1 %91, label %"0x65f", label %"0x5dd"

"0x65f":                                          ; preds = %"0x65b"
  %92 = add nsw i64 %53, -42
  %93 = add i64 %rsp_52, -8
  %94 = inttoptr i64 %93 to i64*
  store i64 1645, i64* %94, align 8, !noalias !0
  store i32 14, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %92, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 42, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %53, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %93, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %95 = tail call { i64, i64 } @cn_mul(i64 %r12_54, i64 %rbp_53, i64 %r13_55, i64 %48)
  br label %"0x649"

"0x672":                                          ; preds = %"0x5e8"
  %96 = add i64 %rsp_52, -8
  %97 = inttoptr i64 %96 to i64*
  store i64 1664, i64* %97, align 8, !noalias !0
  store i32 14, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %54, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 43, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %53, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i64 %96, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %98 = tail call { i64, i64 } @cn_add(i64 %r12_54, i64 %rbp_53, i64 %r13_55, i64 %48)
  br label %"0x649"
}

; Function Attrs: noinline norecurse nounwind
define { i64 } @register_tm_clones() local_unnamed_addr #1 {
"0x720":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %0 = add i64 %rsp_1, -8
  %1 = inttoptr i64 %0 to i64*
  store i64 %rbp_2, i64* %1, align 8, !noalias !0
  %2 = add i64 %rsp_1, 8
  store i32 41, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  tail call void @llvm.memset.p0i8.i64(i8* bitcast (i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3) to i8*), i8 0, i64 16, i32 8, i1 false)
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i64 ptrtoint (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  ret { i64 } zeroinitializer
}

; Function Attrs: noinline norecurse nounwind
define { i64 } @deregister_tm_clones() local_unnamed_addr #1 {
"0x6e0":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %0 = add i64 %rsp_1, -8
  %1 = inttoptr i64 %0 to i64*
  store i64 %rbp_2, i64* %1, align 8, !noalias !0
  %2 = add i64 %rsp_1, 8
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 ptrtoint (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 ptrtoint (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  ret { i64 } { i64 ptrtoint (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64) }
}

; Function Attrs: noinline norecurse nounwind
define void @_fini() local_unnamed_addr #1 {
"0x8c4":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %0 = add i64 %rsp_1, 8
  store i32 9, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %rsp_1, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 8, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  ret void
}

; Function Attrs: noinline
define void @__do_global_dtors_aux() local_unnamed_addr #2 {
"0x770":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %0 = load i64, i64* bitcast (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64*), align 8, !noalias !0
  %1 = and i64 %0, 255
  %2 = icmp eq i64 %1, 0
  br i1 %2, label %"0x779", label %"0x7a8.exit"

"0x779":                                          ; preds = %"0x770"
  %rbp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %3 = add i64 %rsp_1, -8
  %4 = inttoptr i64 %3 to i64*
  store i64 %rbp_2, i64* %4, align 8, !noalias !0
  br i1 icmp eq (void ()* @__cxa_finalize, void ()* null), label %"0x793", label %"0x787"

"0x787":                                          ; preds = %"0x779"
  %5 = add i64 %rsp_1, -16
  %6 = inttoptr i64 %5 to i64*
  store i64 1939, i64* %6, align 8, !noalias !0
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__cxa_finalize to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %5, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %3, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  store i64 ptrtoint (i64** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 29, i32 1) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  tail call void @__jove_call(void ()* @__cxa_finalize)
  %rsp_16 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  br label %"0x793"

"0x793":                                          ; preds = %"0x787", %"0x779"
  %rsp_.0 = phi i64 [ %rsp_16, %"0x787" ], [ %3, %"0x779" ]
  %7 = add i64 %rsp_.0, -8
  %8 = inttoptr i64 %7 to i64*
  store i64 1944, i64* %8, align 8, !noalias !0
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__cxa_finalize to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %7, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %3, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %9 = tail call { i64 } @deregister_tm_clones()
  store i64 ptrtoint (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  %rsp_22 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 1, i64* bitcast (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64*), align 8, !noalias !0
  %10 = add i64 %rsp_22, 16
  %11 = inttoptr i64 %rsp_22 to i64*
  %12 = load i64, i64* %11, align 8, !noalias !0
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 ptrtoint (void ()* @__cxa_finalize to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %12, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  ret void

"0x7a8.exit":                                     ; preds = %"0x770"
  %13 = add i64 %rsp_1, 8
  store i32 14, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %13, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  ret void
}

; Function Attrs: noinline norecurse nounwind
define void @__libc_csu_fini() local_unnamed_addr #1 {
"0x8c0":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %0 = add i64 %rsp_1, 8
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  ret void
}

; Function Attrs: noinline norecurse nounwind
define { i64 } @frame_dummy() local_unnamed_addr #1 {
"0x7b0":
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %rbp_2 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 5), align 8, !alias.scope !0
  %0 = add i64 %rsp_1, -8
  %1 = inttoptr i64 %0 to i64*
  store i64 %rbp_2, i64* %1, align 8, !noalias !0
  %2 = add i64 %rsp_1, 8
  store i32 41, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  tail call void @llvm.memset.p0i8.i64(i8* bitcast (i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3) to i8*), i8 0, i64 16, i32 8, i1 false)
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i64 ptrtoint (%struct.__jove__bss* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 30) to i64), i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !0
  ret { i64 } zeroinitializer
}

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_sub(i64 %rdi, i64 %rsi, i64 %rdx, i64 %rcx) local_unnamed_addr #1 {
"0x7d0":
  %0 = sub i64 %rsi, %rcx
  %1 = sub i64 %rdi, %rdx
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %2 = add i64 %rsp_1, 8
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !0
  store i64 %1, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 8, !alias.scope !0
  store i64 %rdx, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !0
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i64 %0, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  %3 = insertvalue { i64, i64 } undef, i64 %1, 0
  %4 = insertvalue { i64, i64 } %3, i64 %0, 1
  ret { i64, i64 } %4
}

; Function Attrs: noinline
define internal void @"0x580"() local_unnamed_addr #2 {
"0x580":
  tail call void @__jove_call(void ()* nonnull @puts)
  ret void
}

declare void @__jove_indirect_call(void ()*) local_unnamed_addr

declare void @__jove_indirect_jump(void ()*) local_unnamed_addr

; Function Attrs: norecurse nounwind readnone uwtable
declare i64 @helper_mulsh_i64(i64, i64) local_unnamed_addr #3

; Function Attrs: norecurse nounwind readnone uwtable
declare { i64, i64 } @helper_idivq_EAX(i64, i64, i64) local_unnamed_addr #3

; Function Attrs: norecurse nounwind readnone uwtable
declare i64 @helper_cc_compute_all(i64, i64, i64, i32) local_unnamed_addr #3

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #4

declare void @__jove_call(void ()*)

attributes #0 = { noinline noreturn }
attributes #1 = { noinline norecurse nounwind }
attributes #2 = { noinline }
attributes #3 = { norecurse nounwind readnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { argmemonly nounwind }

!0 = !{!1}
!1 = !{!"JoveScope", !2}
!2 = !{!"JoveDomain"}
```
### ARM32
#### Machine Code
```asm
0000068c <cn_add>:
 68c:	b082      	sub	sp, #8
 68e:	b430      	push	{r4, r5}
 690:	b082      	sub	sp, #8
 692:	ac02      	add	r4, sp, #8
 694:	9305      	str	r3, [sp, #20]
 696:	e904 0006 	stmdb	r4, {r1, r2}
 69a:	9906      	ldr	r1, [sp, #24]
 69c:	9d01      	ldr	r5, [sp, #4]
 69e:	9a00      	ldr	r2, [sp, #0]
 6a0:	4429      	add	r1, r5
 6a2:	6041      	str	r1, [r0, #4]
 6a4:	4413      	add	r3, r2
 6a6:	6003      	str	r3, [r0, #0]
 6a8:	b002      	add	sp, #8
 6aa:	bc30      	pop	{r4, r5}
 6ac:	b002      	add	sp, #8
 6ae:	4770      	bx	lr

000006b0 <cn_sub>:
 6b0:	b082      	sub	sp, #8
 6b2:	b430      	push	{r4, r5}
 6b4:	b082      	sub	sp, #8
 6b6:	ac02      	add	r4, sp, #8
 6b8:	9d06      	ldr	r5, [sp, #24]
 6ba:	e904 0006 	stmdb	r4, {r1, r2}
 6be:	9901      	ldr	r1, [sp, #4]
 6c0:	9a00      	ldr	r2, [sp, #0]
 6c2:	9305      	str	r3, [sp, #20]
 6c4:	1b49      	subs	r1, r1, r5
 6c6:	1ad3      	subs	r3, r2, r3
 6c8:	6041      	str	r1, [r0, #4]
 6ca:	6003      	str	r3, [r0, #0]
 6cc:	b002      	add	sp, #8
 6ce:	bc30      	pop	{r4, r5}
 6d0:	b002      	add	sp, #8
 6d2:	4770      	bx	lr

000006d4 <cn_mul>:
 6d4:	b082      	sub	sp, #8
 6d6:	b4f0      	push	{r4, r5, r6, r7}
 6d8:	b082      	sub	sp, #8
 6da:	ac02      	add	r4, sp, #8
 6dc:	9307      	str	r3, [sp, #28]
 6de:	e904 0006 	stmdb	r4, {r1, r2}
 6e2:	9c00      	ldr	r4, [sp, #0]
 6e4:	9a08      	ldr	r2, [sp, #32]
 6e6:	9e01      	ldr	r6, [sp, #4]
 6e8:	fb04 f703 	mul.w	r7, r4, r3
 6ec:	fb04 f402 	mul.w	r4, r4, r2
 6f0:	fb06 4103 	mla	r1, r6, r3, r4
 6f4:	fb06 7212 	mls	r2, r6, r2, r7
 6f8:	6041      	str	r1, [r0, #4]
 6fa:	6002      	str	r2, [r0, #0]
 6fc:	b002      	add	sp, #8
 6fe:	bcf0      	pop	{r4, r5, r6, r7}
 700:	b002      	add	sp, #8
 702:	4770      	bx	lr

00000704 <cn_div>:
 704:	b082      	sub	sp, #8
 706:	e92d 43f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, lr}
 70a:	b083      	sub	sp, #12
 70c:	ad02      	add	r5, sp, #8
 70e:	4680      	mov	r8, r0
 710:	9c0c      	ldr	r4, [sp, #48]	; 0x30
 712:	461f      	mov	r7, r3
 714:	e905 0006 	stmdb	r5, {r1, r2}
 718:	9d01      	ldr	r5, [sp, #4]
 71a:	fb04 f604 	mul.w	r6, r4, r4
 71e:	f8dd 9000 	ldr.w	r9, [sp]
 722:	fb03 6603 	mla	r6, r3, r3, r6
 726:	930b      	str	r3, [sp, #44]	; 0x2c
 728:	fb05 f004 	mul.w	r0, r5, r4
 72c:	fb09 0003 	mla	r0, r9, r3, r0
 730:	4631      	mov	r1, r6
 732:	f000 f811 	bl	758 <__divsi3>
 736:	fb05 f507 	mul.w	r5, r5, r7
 73a:	4631      	mov	r1, r6
 73c:	f8c8 0000 	str.w	r0, [r8]
 740:	fb09 5014 	mls	r0, r9, r4, r5
 744:	f000 f808 	bl	758 <__divsi3>
 748:	f8c8 0004 	str.w	r0, [r8, #4]
 74c:	4640      	mov	r0, r8
 74e:	b003      	add	sp, #12
 750:	e8bd 43f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, lr}
 754:	b002      	add	sp, #8
 756:	4770      	bx	lr

00000758 <__divsi3>:
 758:	2900      	cmp	r1, #0
 75a:	f000 813e 	beq.w	9da <.divsi3_skip_div0_test+0x27c>

0000075e <.divsi3_skip_div0_test>:
 75e:	ea80 0c01 	eor.w	ip, r0, r1
 762:	bf48      	it	mi
 764:	4249      	negmi	r1, r1
 766:	1e4a      	subs	r2, r1, #1
 768:	f000 811f 	beq.w	9aa <.divsi3_skip_div0_test+0x24c>
 76c:	0003      	movs	r3, r0
 76e:	bf48      	it	mi
 770:	4243      	negmi	r3, r0
 772:	428b      	cmp	r3, r1
 774:	f240 811e 	bls.w	9b4 <.divsi3_skip_div0_test+0x256>
 778:	4211      	tst	r1, r2
 77a:	f000 8123 	beq.w	9c4 <.divsi3_skip_div0_test+0x266>
 77e:	fab3 f283 	clz	r2, r3
 782:	fab1 f081 	clz	r0, r1
 786:	eba0 0202 	sub.w	r2, r0, r2
 78a:	f1c2 021f 	rsb	r2, r2, #31
 78e:	a004      	add	r0, pc, #16	; (adr r0, 7a0 <.divsi3_skip_div0_test+0x42>)
 790:	eb00 1202 	add.w	r2, r0, r2, lsl #4
 794:	f04f 0000 	mov.w	r0, #0
 798:	4697      	mov	pc, r2
 79a:	bf00      	nop
 79c:	f3af 8000 	nop.w
 7a0:	ebb3 7fc1 	cmp.w	r3, r1, lsl #31
 7a4:	bf00      	nop
 7a6:	eb40 0000 	adc.w	r0, r0, r0
 7aa:	bf28      	it	cs
 7ac:	eba3 73c1 	subcs.w	r3, r3, r1, lsl #31
 7b0:	ebb3 7f81 	cmp.w	r3, r1, lsl #30
 7b4:	bf00      	nop
 7b6:	eb40 0000 	adc.w	r0, r0, r0
 7ba:	bf28      	it	cs
 7bc:	eba3 7381 	subcs.w	r3, r3, r1, lsl #30
 7c0:	ebb3 7f41 	cmp.w	r3, r1, lsl #29
 7c4:	bf00      	nop
 7c6:	eb40 0000 	adc.w	r0, r0, r0
 7ca:	bf28      	it	cs
 7cc:	eba3 7341 	subcs.w	r3, r3, r1, lsl #29
 7d0:	ebb3 7f01 	cmp.w	r3, r1, lsl #28
 7d4:	bf00      	nop
 7d6:	eb40 0000 	adc.w	r0, r0, r0
 7da:	bf28      	it	cs
 7dc:	eba3 7301 	subcs.w	r3, r3, r1, lsl #28
 7e0:	ebb3 6fc1 	cmp.w	r3, r1, lsl #27
 7e4:	bf00      	nop
 7e6:	eb40 0000 	adc.w	r0, r0, r0
 7ea:	bf28      	it	cs
 7ec:	eba3 63c1 	subcs.w	r3, r3, r1, lsl #27
 7f0:	ebb3 6f81 	cmp.w	r3, r1, lsl #26
 7f4:	bf00      	nop
 7f6:	eb40 0000 	adc.w	r0, r0, r0
 7fa:	bf28      	it	cs
 7fc:	eba3 6381 	subcs.w	r3, r3, r1, lsl #26
 800:	ebb3 6f41 	cmp.w	r3, r1, lsl #25
 804:	bf00      	nop
 806:	eb40 0000 	adc.w	r0, r0, r0
 80a:	bf28      	it	cs
 80c:	eba3 6341 	subcs.w	r3, r3, r1, lsl #25
 810:	ebb3 6f01 	cmp.w	r3, r1, lsl #24
 814:	bf00      	nop
 816:	eb40 0000 	adc.w	r0, r0, r0
 81a:	bf28      	it	cs
 81c:	eba3 6301 	subcs.w	r3, r3, r1, lsl #24
 820:	ebb3 5fc1 	cmp.w	r3, r1, lsl #23
 824:	bf00      	nop
 826:	eb40 0000 	adc.w	r0, r0, r0
 82a:	bf28      	it	cs
 82c:	eba3 53c1 	subcs.w	r3, r3, r1, lsl #23
 830:	ebb3 5f81 	cmp.w	r3, r1, lsl #22
 834:	bf00      	nop
 836:	eb40 0000 	adc.w	r0, r0, r0
 83a:	bf28      	it	cs
 83c:	eba3 5381 	subcs.w	r3, r3, r1, lsl #22
 840:	ebb3 5f41 	cmp.w	r3, r1, lsl #21
 844:	bf00      	nop
 846:	eb40 0000 	adc.w	r0, r0, r0
 84a:	bf28      	it	cs
 84c:	eba3 5341 	subcs.w	r3, r3, r1, lsl #21
 850:	ebb3 5f01 	cmp.w	r3, r1, lsl #20
 854:	bf00      	nop
 856:	eb40 0000 	adc.w	r0, r0, r0
 85a:	bf28      	it	cs
 85c:	eba3 5301 	subcs.w	r3, r3, r1, lsl #20
 860:	ebb3 4fc1 	cmp.w	r3, r1, lsl #19
 864:	bf00      	nop
 866:	eb40 0000 	adc.w	r0, r0, r0
 86a:	bf28      	it	cs
 86c:	eba3 43c1 	subcs.w	r3, r3, r1, lsl #19
 870:	ebb3 4f81 	cmp.w	r3, r1, lsl #18
 874:	bf00      	nop
 876:	eb40 0000 	adc.w	r0, r0, r0
 87a:	bf28      	it	cs
 87c:	eba3 4381 	subcs.w	r3, r3, r1, lsl #18
 880:	ebb3 4f41 	cmp.w	r3, r1, lsl #17
 884:	bf00      	nop
 886:	eb40 0000 	adc.w	r0, r0, r0
 88a:	bf28      	it	cs
 88c:	eba3 4341 	subcs.w	r3, r3, r1, lsl #17
 890:	ebb3 4f01 	cmp.w	r3, r1, lsl #16
 894:	bf00      	nop
 896:	eb40 0000 	adc.w	r0, r0, r0
 89a:	bf28      	it	cs
 89c:	eba3 4301 	subcs.w	r3, r3, r1, lsl #16
 8a0:	ebb3 3fc1 	cmp.w	r3, r1, lsl #15
 8a4:	bf00      	nop
 8a6:	eb40 0000 	adc.w	r0, r0, r0
 8aa:	bf28      	it	cs
 8ac:	eba3 33c1 	subcs.w	r3, r3, r1, lsl #15
 8b0:	ebb3 3f81 	cmp.w	r3, r1, lsl #14
 8b4:	bf00      	nop
 8b6:	eb40 0000 	adc.w	r0, r0, r0
 8ba:	bf28      	it	cs
 8bc:	eba3 3381 	subcs.w	r3, r3, r1, lsl #14
 8c0:	ebb3 3f41 	cmp.w	r3, r1, lsl #13
 8c4:	bf00      	nop
 8c6:	eb40 0000 	adc.w	r0, r0, r0
 8ca:	bf28      	it	cs
 8cc:	eba3 3341 	subcs.w	r3, r3, r1, lsl #13
 8d0:	ebb3 3f01 	cmp.w	r3, r1, lsl #12
 8d4:	bf00      	nop
 8d6:	eb40 0000 	adc.w	r0, r0, r0
 8da:	bf28      	it	cs
 8dc:	eba3 3301 	subcs.w	r3, r3, r1, lsl #12
 8e0:	ebb3 2fc1 	cmp.w	r3, r1, lsl #11
 8e4:	bf00      	nop
 8e6:	eb40 0000 	adc.w	r0, r0, r0
 8ea:	bf28      	it	cs
 8ec:	eba3 23c1 	subcs.w	r3, r3, r1, lsl #11
 8f0:	ebb3 2f81 	cmp.w	r3, r1, lsl #10
 8f4:	bf00      	nop
 8f6:	eb40 0000 	adc.w	r0, r0, r0
 8fa:	bf28      	it	cs
 8fc:	eba3 2381 	subcs.w	r3, r3, r1, lsl #10
 900:	ebb3 2f41 	cmp.w	r3, r1, lsl #9
 904:	bf00      	nop
 906:	eb40 0000 	adc.w	r0, r0, r0
 90a:	bf28      	it	cs
 90c:	eba3 2341 	subcs.w	r3, r3, r1, lsl #9
 910:	ebb3 2f01 	cmp.w	r3, r1, lsl #8
 914:	bf00      	nop
 916:	eb40 0000 	adc.w	r0, r0, r0
 91a:	bf28      	it	cs
 91c:	eba3 2301 	subcs.w	r3, r3, r1, lsl #8
 920:	ebb3 1fc1 	cmp.w	r3, r1, lsl #7
 924:	bf00      	nop
 926:	eb40 0000 	adc.w	r0, r0, r0
 92a:	bf28      	it	cs
 92c:	eba3 13c1 	subcs.w	r3, r3, r1, lsl #7
 930:	ebb3 1f81 	cmp.w	r3, r1, lsl #6
 934:	bf00      	nop
 936:	eb40 0000 	adc.w	r0, r0, r0
 93a:	bf28      	it	cs
 93c:	eba3 1381 	subcs.w	r3, r3, r1, lsl #6
 940:	ebb3 1f41 	cmp.w	r3, r1, lsl #5
 944:	bf00      	nop
 946:	eb40 0000 	adc.w	r0, r0, r0
 94a:	bf28      	it	cs
 94c:	eba3 1341 	subcs.w	r3, r3, r1, lsl #5
 950:	ebb3 1f01 	cmp.w	r3, r1, lsl #4
 954:	bf00      	nop
 956:	eb40 0000 	adc.w	r0, r0, r0
 95a:	bf28      	it	cs
 95c:	eba3 1301 	subcs.w	r3, r3, r1, lsl #4
 960:	ebb3 0fc1 	cmp.w	r3, r1, lsl #3
 964:	bf00      	nop
 966:	eb40 0000 	adc.w	r0, r0, r0
 96a:	bf28      	it	cs
 96c:	eba3 03c1 	subcs.w	r3, r3, r1, lsl #3
 970:	ebb3 0f81 	cmp.w	r3, r1, lsl #2
 974:	bf00      	nop
 976:	eb40 0000 	adc.w	r0, r0, r0
 97a:	bf28      	it	cs
 97c:	eba3 0381 	subcs.w	r3, r3, r1, lsl #2__aeabi_idivmod
 980:	ebb3 0f41 	cmp.w	r3, r1, lsl #1
 984:	bf00      	nop
 986:	eb40 0000 	adc.w	r0, r0, r0
 98a:	bf28      	it	cs
 98c:	eba3 0341 	subcs.w	r3, r3, r1, lsl #1
 990:	ebb3 0f01 	cmp.w	r3, r1
 994:	bf00      	nop
 996:	eb40 0000 	adc.w	r0, r0, r0
 99a:	bf28      	it	cs
 99c:	eba3 0301 	subcs.w	r3, r3, r1
 9a0:	f1bc 0f00 	cmp.w	ip, #0
 9a4:	bf48      	it	mi
 9a6:	4240      	negmi	r0, r0
 9a8:	4770      	bx	lr
 9aa:	ea9c 0f00 	teq	ip, r0
 9ae:	bf48      	it	mi
 9b0:	4240      	negmi	r0, r0
 9b2:	4770      	bx	lr
 9b4:	bf38      	it	cc
 9b6:	2000      	movcc	r0, #0
 9b8:	bf04      	itt	eq
 9ba:	ea4f 70ec 	moveq.w	r0, ip, asr #31
 9be:	f040 0001 	orreq.w	r0, r0, #1
 9c2:	4770      	bx	lr
 9c4:	fab1 f281 	clz	r2, r1
 9c8:	f1c2 021f 	rsb	r2, r2, #31
 9cc:	f1bc 0f00 	cmp.w	ip, #0
 9d0:	fa23 f002 	lsr.w	r0, r3, r2
 9d4:	bf48      	it	mi
 9d6:	4240      	negmi	r0, r0
 9d8:	4770      	bx	lr
 9da:	2800      	cmp	r0, #0
 9dc:	bfc8      	it	gt
 9de:	f06f 4000 	mvngt.w	r0, #2147483648	; 0x80000000
 9e2:	bfb8      	it	lt
 9e4:	f04f 4000 	movlt.w	r0, #2147483648	; 0x80000000
 9e8:	f000 b80e 	b.w	a08 <__aeabi_idiv0>

000009ec <__aeabi_idivmod>:
 9ec:	2900      	cmp	r1, #0
 9ee:	d0f4      	beq.n	9da <.divsi3_skip_div0_test+0x27c>
 9f0:	e92d 4003 	stmdb	sp!, {r0, r1, lr}
 9f4:	f7ff feb3 	bl	75e <.divsi3_skip_div0_test>
 9f8:	e8bd 4006 	ldmia.w	sp!, {r1, r2, lr}
 9fc:	fb02 f300 	mul.w	r3, r2, r0
 a00:	eba1 0103 	sub.w	r1, r1, r3
 a04:	4770      	bx	lr
 a06:	bf00      	nop

00000a08 <__aeabi_idiv0>:
 a08:	b502      	push	{r1, lr}
 a0a:	f04f 0008 	mov.w	r0, #8
 a0e:	f7ff ed38 	blx	480 <raise@plt>
 a12:	bd02      	pop	{r1, pc}
```
#### Running Jove
```bash
$ # $PWD is $JOVE_SRC_DIR/bin/arm
$ ./jove-init ../../tests/bin/gcc/debian-jessie/arm/complex-num
File: ../../tests/bin/gcc/debian-jessie/arm/complex-num
Format: ELF32-arm-little
Arch: arm
AddressSize: 32bit
MC TheTriple: armv7-unknown-unknown-elf
MC TheTarget: ARM
Thumb TheTriple: thumbv7-unknown-unknown-elf
Thumb TheTarget: Thumb

Address Space:
.interp              [154, 16d)
.note.ABI-tag        [170, 190)
.note.gnu.build-id   [190, 1b4)
.dynsym              [1b4, 274)
.dynstr              [274, 322)
.gnu.hash            [324, 33c)
.gnu.version         [33c, 354)
.gnu.version_r       [354, 374)
.rel.dyn             [374, 3cc)
.rel.plt             [3cc, 40c)
.init                [40c, 418)
.plt                 [418, 48c)
.text                [490, a58)
.fini                [a58, a60)
.rodata              [a60, a94)
.ARM.exidx           [a94, a9c)
.eh_frame            [a9c, aa0)
.eh_frame_hdr        [aa0, aa8)
.dynamic             [1aa8, 1b98)
.data                [1b98, 1ba0)
.jcr                 [1ba0, 1ba4)
.fini_array          [1ba4, 1ba8)
.init_array          [1ba8, 1bac)
.got                 [1bac, 1bf8)
.bss                 [1bf8, 1bf9)

Relocations:

  RELATIVE     @ 1b9c             +0               
  RELATIVE     @ 1ba4             +0               
  RELATIVE     @ 1ba8             +0               
  RELATIVE     @ 1bac             +0               
  RELATIVE     @ 1bb0             +0               
  RELATIVE     @ 1bb4             +0               
  ADDRESSOF    @ 1bb8             +0               __gmon_start__                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1bbc             +0               _ITM_deregisterTMCloneTable    *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1bc0             +0               _ITM_registerTMCloneTable      *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1bc4             +0               __cxa_finalize                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1bc8             +0               _Jv_RegisterClasses            *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1bd8             +0               __libc_start_main              *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1bdc             +0               abort                          *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1be0             +0               __gmon_start__                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1be4             +0               __cxa_finalize                 *FUNCTION   *WEAK     @ 0 {0}
  ADDRESSOF    @ 1be8             +0               puts                           *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1bec             +0               strtol                         *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1bf0             +0               printf                         *FUNCTION   *GLOBAL   @ 0 {0}
  ADDRESSOF    @ 1bf4             +0               raise                          *FUNCTION   *GLOBAL   @ 0 {0}

Exported Functions:

  _init                                    @ 40c              {A}
  main                                     @ 490              {T}
  _start                                   @ 550              {T}
  call_weak_fn                             @ 598              {A}
  deregister_tm_clones                     @ 5bc              {T}
  register_tm_clones                       @ 5ec              {T}
  __do_global_dtors_aux                    @ 620              {T}
  frame_dummy                              @ 660              {T}
  cn_add                                   @ 68c              {T}
  cn_sub                                   @ 6b0              {T}
  cn_mul                                   @ 6d4              {T}
  cn_div                                   @ 704              {T}
  __divsi3                                 @ 758              {T}
  __aeabi_idivmod                          @ 9ec              {T}
  __aeabi_idiv0                            @ a08              {T}
  __libc_csu_init                          @ a14              {T}
  __libc_csu_fini                          @ a54              {T}
  _fini                                    @ a58              {A}

Translating arm machine code to QEMU IR...

6d4
  6d4 {T}
    note: return
660
  660 {T}
    note: conditional jump to 674 and 66e
  674 {T}
    note: conditional jump to 66e and 67c
  66e {T}
    note: unconditional jump to 5ec
  5ec {T}
    note: conditional jump to 60c and 604
  60c {T}
    note: return
  604 {T}
    note: conditional jump to 60c and 60a
  60a {T}
    note: indirect jump
  67c {T}
    note: indirect call
  67e {T}
    note: unconditional jump to 66e
550
  550 {T}
    note: direct call to 42c
  584 {T}
    note: direct call to 438
  588 {T}
  note: invalid instruction @ 588
620
  620 {T}
    note: conditional jump to 64a and 62e
  64a {T}
    note: return
  62e {T}
    note: conditional jump to 63e and 634
  63e {T}
    note: direct call to 5bc
  642 {T}
    note: return
  634 {T}
    note: direct call to 450
758
  758 {T}
    note: conditional jump to 9da and 75e
  9da {T}
    note: unconditional jump to a08
  a08 {T}
    note: direct call to 480
  a12 {T}
    note: return
  75e {T}
    note: conditional jump to 9aa and 76c
  9aa {T}
    note: return
  76c {T}
    note: conditional jump to 9b4 and 778
  9b4 {T}
    note: return
  778 {T}
    note: conditional jump to 9c4 and 77e
  9c4 {T}
    note: return
  77e {T}
    note: indirect jump
68c
  68c {T}
    note: return
598
  598 {A}
    note: unconditional jump to 5b0
  5b0 {A}
    note: unconditional jump to 444
  444 {A}
    note: indirect jump
5bc
  5bc {T}
    note: conditional jump to 5d8 and 5d0
  5d8 {T}
    note: return
  5d0 {T}
    note: conditional jump to 5d8 and 5d6
  5d6 {T}
    note: indirect jump
9ec
  9ec {T}
    note: conditional jump to 9da and 9f0
  9da {T}
    note: unconditional jump to a08
  a08 {T}
    note: direct call to 480
  a12 {T}
    note: return
  9f0 {T}
    note: direct call to 75e
  9f8 {T}
    note: return
a08
  a08 {T}
    note: direct call to 480
  a12 {T}
    note: return
a54
  a54 {T}
    note: return
a14
  a14 {T}
    note: direct call to 40c
  a28 {T}
    note: conditional jump to a46 and a30
  a46 {T}
    note: return
  a30 {T}
    note: indirect call
  a42 {T}
    note: conditional jump to a34 and a46
  a34 {T}
    note: indirect call
490
  490 {T}
    note: conditional jump to 4a6 and 498
  4a6 {T}
    note: direct call to 468
  4b2 {T}
    note: direct call to 468
  4be {T}
    note: direct call to 468
  4ca {T}
    note: direct call to 468
  4d6 {T}
    note: conditional jump to 542 and 4e2
  542 {T}
    note: unconditional jump to 4a2
  4a2 {T}
    note: return
  4e2 {T}
    note: indirect jump
  498 {T}
    note: direct call to 45c
  4a0 {T}
    note: return
704
  704 {T}
    note: direct call to 758
  736 {T}
    note: direct call to 758
  748 {T}
    note: return
a58
  a58 {A}
    note: return
6b0
  6b0 {T}
    note: return
5ec
  5ec {T}
    note: conditional jump to 60c and 604
  60c {T}
    note: return
  604 {T}
    note: conditional jump to 60c and 60a
  60a {T}
    note: indirect jump
40c
  40c {A}
    note: direct call to 598
  414 {A}
    note: return
42c
  42c {A}
    note: indirect jump
438
  438 {A}
    note: indirect jump
450
  450 {A}
    note: indirect jump
480
  480 {A}
    note: indirect jump
75e
  75e {T}
    note: conditional jump to 9aa and 76c
  9aa {T}
    note: return
  76c {T}
    note: conditional jump to 9b4 and 778
  9b4 {T}
    note: return
  778 {T}
    note: conditional jump to 9c4 and 77e
  9c4 {T}
    note: return
  77e {T}
    note: indirect jump
468
  468 {A}
    note: indirect jump
45c
  45c {A}
    note: indirect jump

Translating QEMU IR to LLVM...

45c
  45c
    note: PC-relative expression @ 45c
468
  468
    note: PC-relative expression @ 468
480
  480
    note: PC-relative expression @ 480
450
  450
    note: PC-relative expression @ 450
438
  438
    note: PC-relative expression @ 438
42c
  42c
    note: PC-relative expression @ 42c
40c
  40c
  414
75e
  75e
  9aa
  76c
  9b4
  778
  9c4
  77e
    note: PC-relative expression @ 78e
5ec
  5ec
    note: PC-relative expression @ 5ec
    note: PC-relative expression @ 5ee
    note: PC-relative expression @ 5f0
    note: PC-relative expression @ 5f2
    note: PC-relative expression @ 5f4
    note: PC-relative expression @ 5f8
  60c
  604
    note: PC-relative expression @ 604
  60a
68c
  68c
758
  758
  9da
  a08
  a12
  75e
  9aa
  76c
  9b4
  778
  9c4
  77e
    note: PC-relative expression @ 78e
620
  620
    note: PC-relative expression @ 622
    note: PC-relative expression @ 624
    note: PC-relative expression @ 626
    note: PC-relative expression @ 628
  64a
  62e
    note: PC-relative expression @ 62e
  63e
  642
    note: PC-relative expression @ 642
    note: PC-relative expression @ 646
  634
    note: PC-relative expression @ 634
    note: PC-relative expression @ 636
598
  598
    note: PC-relative expression @ 598
    note: PC-relative expression @ 59c
    note: PC-relative expression @ 5a0
  5b0
  444
    note: PC-relative expression @ 444
550
  550
    note: PC-relative expression @ 560
    note: PC-relative expression @ 564
    note: PC-relative expression @ 568
    note: PC-relative expression @ 574
    note: PC-relative expression @ 57a
  584
    warning: unreachable code
660
  660
    note: PC-relative expression @ 660
    note: PC-relative expression @ 664
    note: PC-relative expression @ 668
    note: PC-relative expression @ 66a
  674
    note: PC-relative expression @ 674
  66e
  5ec
    note: PC-relative expression @ 5ec
    note: PC-relative expression @ 5ee
    note: PC-relative expression @ 5f0
    note: PC-relative expression @ 5f2
    note: PC-relative expression @ 5f4
    note: PC-relative expression @ 5f8
  60c
  604
    note: PC-relative expression @ 604
  60a
  67c
    note: PC-relative expression @ 67c
  67e
6d4
  6d4
5bc
  5bc
    note: PC-relative expression @ 5bc
    note: PC-relative expression @ 5be
    note: PC-relative expression @ 5c0
    note: PC-relative expression @ 5c2
    note: PC-relative expression @ 5c4
    note: PC-relative expression @ 5ca
  5d8
  5d0
    note: PC-relative expression @ 5d0
  5d6
9ec
  9ec
  9da
  a08
  a12
  9f0
  9f8
a08
  a08
  a12
a54
  a54
a14
  a14
    note: PC-relative expression @ a1a
    note: PC-relative expression @ a1e
    note: PC-relative expression @ a22
  a28
    note: PC-relative expression @ a28
  a46
  a30
    note: PC-relative expression @ a40
  a42
  a34
    note: PC-relative expression @ a40
a58
  a58
490
  490
  4a6
  4b2
  4be
  4ca
  4d6
  542
  4a2
  4e2
    note: PC-relative expression @ 4e2
    note: PC-relative expression @ 4e2
  498
    note: PC-relative expression @ 498
    note: PC-relative expression @ 49a
  4a0
6b0
  6b0
704
  704
  736
  748
```
#### LLVM
```llvm
%struct.CPUARMState = type { [16 x i32], [32 x i64], i64, i32, i32, i32, i32, [8 x i64], [8 x i32], [8 x i32], [5 x i32], [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, i64, [4 x i64], [4 x i64], %struct.anon.16.272, %struct.anon.47, %struct.anon.48, i32, i32, %struct.anon.49, i64, i64, i64, i64, i32, %struct.anon.50, i32, [16 x %struct.CPUBreakpoint*], [16 x %struct.CPUWatchpoint*], i64, %struct.anon.51, i8*, %struct.arm_boot_info* }
%struct.anon.16.272 = type { i32, %union.anon.17, %union.anon.17, i64, [4 x i64], i32, i64, i32, %union.anon.17, %union.anon.17, i64, [4 x %struct.TCR], %struct.TCR, i32, i32, %union.anon.25, i32, i32, i64, i64, %union.anon.25, %union.anon.17, [8 x i32], %union.anon.33, i64, %union.anon.17, i32, i32, i32, i64, i64, i32, i32, i32, i32, %union.anon.37, %union.anon.17, i32, %struct.EventNotifier, %union.anon.17, %union.anon.17, i64, i64, i64, %union.anon, i64, i64, i32, i64, [4 x %struct.Int128], i32, i32, i32, i32, i32, i32, i32, i32, i32, [16 x i64], [16 x i64], [16 x i64], [16 x i64], i64, i64, i64, i64, i64, i64, i64, i64 }
%struct.TCR = type { i64, i32, i32 }
%union.anon.25 = type { %struct.Int128 }
%struct.Int128 = type { i64, i64 }
%union.anon.33 = type { %struct.anon.34 }
%struct.anon.34 = type { i64, i32, i32, i32, i32, i64 }
%union.anon.37 = type { %struct.anon.38 }
%struct.anon.38 = type { i64, i32, i32, i64, i32, i32 }
%struct.EventNotifier = type { i32, i32 }
%union.anon.17 = type { %struct.anon.18.270 }
%struct.anon.18.270 = type { i64, i64, i64, i64 }
%union.anon = type { i64 }
%struct.anon.47 = type { i32, i32, i32, i32, i32, i32 }
%struct.anon.48 = type { i32, i32, i64, i32 }
%struct.anon.49 = type { [64 x i64], [16 x i32], i32, i32, [8 x i32], %struct.float_status, %struct.float_status }
%struct.float_status = type { i8, i8, i8, i8, i8, i8, i8 }
%struct.anon.50 = type { [16 x i64], i64, [16 x i32] }
%struct.CPUBreakpoint = type { i64, i32, %struct.anon.20 }
%struct.anon.20 = type { %struct.CPUBreakpoint*, %struct.CPUBreakpoint** }
%struct.CPUWatchpoint = type { i64, i64, i64, %struct.MemTxAttrs, i32, %struct.anon.21 }
%struct.MemTxAttrs = type { i24 }
%struct.anon.21 = type { %struct.CPUWatchpoint*, %struct.CPUWatchpoint** }
%struct.anon.51 = type { i32*, i32*, i32* }
%struct.arm_boot_info = type { i64, i8*, i8*, i8*, i8*, i64, i64, i64, i64, i32, i32, i8, i32 (%struct.arm_boot_info*, i8*)*, void (%struct.ARMCPU*, %struct.arm_boot_info*)*, void (%struct.ARMCPU*, %struct.arm_boot_info*)*, i8* (%struct.arm_boot_info*, i32*)*, void (%struct.arm_boot_info*, i8*)*, %struct.ArmLoadKernelNotifier, i32, i64, i64, i64, i8, i64, void (%struct.ARMCPU*, %struct.arm_boot_info*)*, i8, i32 }
%struct.ArmLoadKernelNotifier = type { %struct.Notifier, %struct.ARMCPU* }
%struct.Notifier = type { void (%struct.Notifier*, i8*)*, %struct.anon.5 }
%struct.anon.5 = type { %struct.Notifier*, %struct.Notifier** }
%struct.ARMCPU = type { %struct.CPUState, %struct.CPUARMState, %struct._GHashTable*, i64*, i64*, i32, i64*, i64*, i32, [4 x %struct.QEMUTimer*], [4 x %struct.IRQState*], %struct.MemoryRegion*, i8*, i32, i8, i8, i8, i8, i32, i32, i32, [7 x i32], i8, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i32, i64, [16 x i32], i64, i32, i8, i32, i64 }
%struct.CPUState = type { %struct.DeviceState, i32, i32, i32, %union.anon.0*, i32, i32, i8, %struct.QemuCond*, i8, i8, i8, i8, i8, i8, i32, i32, i64, [1 x %struct.__jmp_buf_tag], %struct.QemuMutex, %struct.qemu_work_item*, %struct.qemu_work_item*, %struct.CPUAddressSpace*, i32, %struct.AddressSpace*, %struct.MemoryRegion*, i8*, %struct.TranslationBlock*, [4096 x %struct.TranslationBlock*], %struct.GDBRegisterState*, i32, i32, %struct.anon.19, %struct.anon.20, %struct.anon.21, %struct.CPUWatchpoint*, i8*, i32, i64, i32, i8, %struct.KVMState*, %struct.kvm_run*, i32, i32, %union.anon.0, i32, i32, i8, i32 }
%struct.DeviceState = type { %struct.Object, i8*, i8, i8, %struct.QemuOpts*, i32, %struct.BusState*, %struct.anon.1, %struct.anon.3, i32, i32, i32 }
%struct.Object = type { %struct.ObjectClass*, void (i8*)*, %struct._GHashTable*, i32, %struct.Object* }
%struct.ObjectClass = type { %struct.TypeImpl*, %struct._GSList*, [4 x i8*], [4 x i8*], void (%struct.Object*)*, %struct._GHashTable* }
%struct.TypeImpl = type { i8*, i32, i32, void (%struct.ObjectClass*, i8*)*, void (%struct.ObjectClass*, i8*)*, void (%struct.ObjectClass*, i8*)*, i8*, void (%struct.Object*)*, void (%struct.Object*)*, void (%struct.Object*)*, i8, i8*, %struct.TypeImpl*, %struct.ObjectClass*, i32, [32 x %struct.InterfaceInfo] }
%struct.InterfaceInfo = type { i8* }
%struct._GSList = type { i8*, %struct._GSList* }
%struct.QemuOpts = type { i8*, %struct.QemuOptsList*, %struct.Location, %struct.anon.0.36, %struct.anon.33 }
%struct.QemuOptsList = type { i8*, i8*, i8, %struct.anon.33, [0 x %struct.QemuOptDesc] }
%struct.QemuOptDesc = type { i8*, i32, i8*, i8* }
%struct.Location = type { i32, i32, i8*, %struct.Location* }
%struct.anon.0.36 = type { %struct.QemuOpt*, %struct.QemuOpt** }
%struct.QemuOpt = type { i8*, i8*, %struct.QemuOptDesc*, %union.anon, %struct.QemuOpts*, %struct.anon.0.36 }
%struct.anon.33 = type { %struct.QemuOpts*, %struct.QemuOpts** }
%struct.BusState = type { %struct.Object, %struct.DeviceState*, i8*, %struct.FWPathProvider*, i32, i8, %struct.anon.61, %struct.anon.0 }
%struct.FWPathProvider = type { %struct.Object }
%struct.anon.61 = type { %struct.BusChild*, %struct.BusChild** }
%struct.BusChild = type { %struct.DeviceState*, i32, %struct.anon.61 }
%struct.anon.0 = type { %struct.BusState*, %struct.BusState** }
%struct.anon.1 = type { %struct.NamedGPIOList* }
%struct.NamedGPIOList = type { i8*, %struct.IRQState**, i32, i32, %struct.anon.2 }
%struct.IRQState = type { %struct.Object, void (i8*, i32, i32)*, i8*, i32 }
%struct.anon.2 = type { %struct.NamedGPIOList*, %struct.NamedGPIOList** }
%struct.anon.3 = type { %struct.BusState* }
%struct.QemuCond = type { %union.pthread_cond_t }
%union.pthread_cond_t = type { %struct.anon.7 }
%struct.anon.7 = type { %union.anon, %union.anon, [2 x i32], [2 x i32], i32, i32, [2 x i32] }
%struct.__jmp_buf_tag = type { [6 x i32], i32, %struct.__sigset_t }
%struct.__sigset_t = type { [32 x i32] }
%struct.QemuMutex = type { %union.pthread_mutex_t }
%union.pthread_mutex_t = type { %struct.__pthread_mutex_s }
%struct.__pthread_mutex_s = type { i32, i32, i32, i32, i32, %union.anon.11 }
%union.anon.11 = type { %struct.__pthread_internal_slist }
%struct.__pthread_internal_slist = type { %struct.__pthread_internal_slist* }
%struct.qemu_work_item = type { %struct.qemu_work_item*, void (i8*)*, i8*, i32, i8 }
%struct.CPUAddressSpace = type opaque
%struct.AddressSpace = type { %struct.rcu_head, i8*, %struct.MemoryRegion*, i32, i8, %struct.FlatView*, i32, %struct.MemoryRegionIoeventfd*, %struct.AddressSpaceDispatch*, %struct.AddressSpaceDispatch*, %struct.MemoryListener, %struct.anon.18 }
%struct.rcu_head = type { %struct.rcu_head*, void (%struct.rcu_head*)* }
%struct.FlatView = type opaque
%struct.MemoryRegionIoeventfd = type opaque
%struct.AddressSpaceDispatch = type opaque
%struct.MemoryListener = type { void (%struct.MemoryListener*)*, void (%struct.MemoryListener*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i32, i32)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i32, i32)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*)*, void (%struct.MemoryListener*)*, void (%struct.MemoryListener*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i1, i64, %struct.EventNotifier*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i1, i64, %struct.EventNotifier*)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i64, i64)*, void (%struct.MemoryListener*, %struct.MemoryRegionSection*, i64, i64)*, i32, %struct.AddressSpace*, %struct.anon.17 }
%struct.MemoryRegionSection = type { %struct.MemoryRegion*, %struct.AddressSpace*, i64, %struct.Int128, i64, i8 }
%struct.anon.17 = type { %struct.MemoryListener*, %struct.MemoryListener** }
%struct.anon.18 = type { %struct.AddressSpace*, %struct.AddressSpace** }
%struct.TranslationBlock = type { i32, i32, i64, i16, i16, i32, i8*, i8*, %struct.TranslationBlock*, %struct.TranslationBlock*, [2 x %struct.TranslationBlock*], [2 x i32], [2 x i16], [2 x i16], [2 x %struct.TranslationBlock*], %struct.TranslationBlock* }
%struct.GDBRegisterState = type { i32, i32, i32 (%struct.CPUARMState*, i8*, i32)*, i32 (%struct.CPUARMState*, i8*, i32)*, i8*, %struct.GDBRegisterState* }
%struct.anon.19 = type { %struct.CPUState*, %struct.CPUState** }
%struct.KVMState = type opaque
%struct.kvm_run = type opaque
%union.anon.0 = type { i32 }
%struct._GHashTable = type opaque
%struct.QEMUTimer = type { i64, %struct.QEMUTimerList*, void (i8*)*, i8*, %struct.QEMUTimer*, i32 }
%struct.QEMUTimerList = type opaque
%struct.MemoryRegion = type { %struct.Object, i8, i8, i8, i8, i8, i8, i8, i8, %struct.RAMBlock*, %struct.Object*, %struct.MemoryRegionIOMMUOps*, %struct.MemoryRegionOps*, i8*, %struct.MemoryRegion*, %struct.Int128, i64, void (%struct.MemoryRegion*)*, i64, i8, i8, i8, i8, i8, %struct.MemoryRegion*, i64, i32, i8, %struct.subregions, %struct.subregions, %struct.coalesced_ranges, i8*, i32, %struct.MemoryRegionIoeventfd*, %struct.NotifierList }
%struct.RAMBlock = type opaque
%struct.MemoryRegionIOMMUOps = type { void (%struct.IOMMUTLBEntry*, %struct.MemoryRegion*, i64, i1)* }
%struct.IOMMUTLBEntry = type { %struct.AddressSpace*, i64, i64, i64, i32 }
%struct.MemoryRegionOps = type { i64 (i8*, i64, i32)*, void (i8*, i64, i64, i32)*, i32 (i8*, i64, i64*, i32, %struct.MemTxAttrs*)*, i32 (i8*, i64, i64, i32, %struct.MemTxAttrs*)*, i32, %struct.anon.13, %struct.anon.14, %struct.MemoryRegionMmio }
%struct.anon.13 = type { i32, i32, i8, i1 (i8*, i64, i32, i1)* }
%struct.anon.14 = type { i32, i32, i8 }
%struct.MemoryRegionMmio = type { [3 x i32 (i8*, i64)*], [3 x void (i8*, i64, i32)*] }
%struct.subregions = type { %struct.MemoryRegion*, %struct.MemoryRegion** }
%struct.coalesced_ranges = type { %struct.CoalescedMemoryRange*, %struct.CoalescedMemoryRange** }
%struct.CoalescedMemoryRange = type opaque
%struct.NotifierList = type { %struct.anon.16 }
%struct.anon.16 = type { %struct.Notifier* }
%struct.__jove_sections = type <{ %struct.__jove__interp, [3 x i8], %struct.__jove__note_ABI-tag, %struct.__jove__note_gnu_build-id, %struct.__jove__dynsym, %struct.__jove__dynstr, [2 x i8], %struct.__jove__gnu_hash, %struct.__jove__gnu_version, %struct.__jove__gnu_version_r, %struct.__jove__rel_dyn, %struct.__jove__rel_plt, %struct.__jove__init, %struct.__jove__plt, [4 x i8], %struct.__jove__text, %struct.__jove__fini, %struct.__jove__rodata, %struct.__jove__ARM_exidx, %struct.__jove__eh_frame, %struct.__jove__eh_frame_hdr, [4096 x i8], %struct.__jove__dynamic, %struct.__jove__data, %struct.__jove__jcr, %struct.__jove__fini_array, %struct.__jove__init_array, %struct.__jove__got, %struct.__jove__bss }>
%struct.__jove__interp = type <{ [25 x i8] }>
%struct.__jove__note_ABI-tag = type <{ [32 x i8] }>
%struct.__jove__note_gnu_build-id = type <{ [36 x i8] }>
%struct.__jove__dynsym = type <{ [192 x i8] }>
%struct.__jove__dynstr = type <{ [174 x i8] }>
%struct.__jove__gnu_hash = type <{ [24 x i8] }>
%struct.__jove__gnu_version = type <{ [24 x i8] }>
%struct.__jove__gnu_version_r = type <{ [32 x i8] }>
%struct.__jove__rel_dyn = type <{ [88 x i8] }>
%struct.__jove__rel_plt = type <{ [64 x i8] }>
%struct.__jove__init = type <{ [12 x i8] }>
%struct.__jove__plt = type <{ [116 x i8] }>
%struct.__jove__text = type <{ [1480 x i8] }>
%struct.__jove__fini = type <{ [8 x i8] }>
%struct.__jove__rodata = type <{ [52 x i8] }>
%struct.__jove__ARM_exidx = type <{ [8 x i8] }>
%struct.__jove__eh_frame = type <{ [4 x i8] }>
%struct.__jove__eh_frame_hdr = type <{ [8 x i8] }>
%struct.__jove__dynamic = type <{ [240 x i8] }>
%struct.__jove__data = type <{ [4 x i8], i32* }>
%struct.__jove__jcr = type <{ [4 x i8] }>
%struct.__jove__fini_array = type <{ i32* }>
%struct.__jove__init_array = type <{ i32* }>
%struct.__jove__got = type <{ i32*, i32*, i32*, void ()*, void ()*, void ()*, void ()*, void ()*, [12 x i8], void ()*, void ()*, void ()*, void ()*, void ()*, void ()*, void ()*, void ()* }>
%struct.__jove__bss = type <{ [1 x i8] }>

@cpu_state = external thread_local local_unnamed_addr global %struct.CPUARMState
@__jove_sections = global %struct.__jove_sections <{ %struct.__jove__interp <{ [25 x i8] c"/lib/ld-linux-armhf.so.3\00" }>, [3 x i8] zeroinitializer, %struct.__jove__note_ABI-tag <{ [32 x i8] c"\04\00\00\00\10\00\00\00\01\00\00\00GNU\00\00\00\00\00\02\00\00\00\06\00\00\00 \00\00\00" }>, %struct.__jove__note_gnu_build-id <{ [36 x i8] c"\04\00\00\00\14\00\00\00\03\00\00\00GNU\00\EE\09\89\C8\B1m\E0\A5,;s\98\DC\8Ej\0DO%g3" }>, %struct.__jove__dynsym <{ [192 x i8] c"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\12\00\00\00\1B\00\00\00\00\00\00\00\00\00\00\00\12\00\00\00!\00\00\00\00\00\00\00\00\00\00\00\12\00\00\003\00\00\00\00\00\00\00\00\00\00\00 \00\00\00B\00\00\00\00\00\00\00\00\00\00\00 \00\00\00^\00\00\00\00\00\00\00\00\00\00\00 \00\00\00x\00\00\00\00\00\00\00\00\00\00\00\22\00\00\00\87\00\00\00\00\00\00\00\00\00\00\00 \00\00\00\9B\00\00\00\00\00\00\00\00\00\00\00\12\00\00\00\A0\00\00\00\00\00\00\00\00\00\00\00\12\00\00\00\A7\00\00\00\00\00\00\00\00\00\00\00\12\00\00\00" }>, %struct.__jove__dynstr <{ [174 x i8] c"\00raise\00GLIBC_2.4\00libc.so.6\00abort\00__libc_start_main\00__gmon_start__\00_ITM_deregisterTMCloneTable\00_ITM_registerTMCloneTable\00__cxa_finalize\00_Jv_RegisterClasses\00puts\00strtol\00printf\00" }>, [2 x i8] zeroinitializer, %struct.__jove__gnu_hash <{ [24 x i8] c"\01\00\00\00\0C\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__gnu_version <{ [24 x i8] c"\00\00\02\00\02\00\02\00\00\00\00\00\00\00\02\00\00\00\02\00\02\00\02\00" }>, %struct.__jove__gnu_version_r <{ [32 x i8] c"\01\00\01\00\11\00\00\00\10\00\00\00\00\00\00\00\14ii\0D\00\00\02\00\07\00\00\00\00\00\00\00" }>, %struct.__jove__rel_dyn <{ [88 x i8] c"\9C\1B\00\00\17\00\00\00\A4\1B\00\00\17\00\00\00\A8\1B\00\00\17\00\00\00\AC\1B\00\00\17\00\00\00\B0\1B\00\00\17\00\00\00\B4\1B\00\00\17\00\00\00\B8\1B\00\00\15\04\00\00\BC\1B\00\00\15\05\00\00\C0\1B\00\00\15\06\00\00\C4\1B\00\00\15\07\00\00\C8\1B\00\00\15\08\00\00" }>, %struct.__jove__rel_plt <{ [64 x i8] c"\D8\1B\00\00\16\03\00\00\DC\1B\00\00\16\02\00\00\E0\1B\00\00\16\04\00\00\E4\1B\00\00\16\07\00\00\E8\1B\00\00\16\09\00\00\EC\1B\00\00\16\0A\00\00\F0\1B\00\00\16\0B\00\00\F4\1B\00\00\16\01\00\00" }>, %struct.__jove__init <{ [12 x i8] c"\08@-\E9`\00\00\EB\08\80\BD\E8" }>, %struct.__jove__plt <{ [116 x i8] c"\04\E0-\E5\04\E0\9F\E5\0E\E0\8F\E0\08\F0\BE\E5\A4\17\00\00\00\C6\8F\E2\01\CA\8C\E2\A4\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2\9C\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2\94\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2\8C\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2\84\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2|\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2t\F7\BC\E5\00\C6\8F\E2\01\CA\8C\E2l\F7\BC\E5" }>, [4 x i8] zeroinitializer, %struct.__jove__text <{ [1480 x i8] c"\06(\10\B5\88\B0\06\D0+HxD\FF\F7\DE\EF\00 \08\B0\10\BD\0CFHh\0A\22\00!\FF\F7\DC\EF\00!\0A\22\02\90\A0h\FF\F7\D6\EF\00!\0A\22\03\90 i\FF\F7\D0\EF\00!\0A\22\04\90`i\FF\F7\CA\EF\E3h\1Bx*;\05\90\05+/\D8\DF\E8\03\F0%\1C.\13.\03\05\9C\02\AA\04\9B\06\A8\06\CA\00\94\00\F0\04\F9\13H\06\99xD\07\9A\FF\F7\B6\EF\00 \CA\E7\05\9C\02\AA\04\9B\06\A8\06\CA\00\94\00\F0\CA\F8\EE\E7\05\9C\02\AA\04\9B\06\A8\06\CA\00\94\00\F0\AF\F8\E5\E7\05\9C\02\AA\04\9B\06\A8\06\CA\00\94\00\F0\CA\F8\DC\E7\01 \AD\E7\00\BF\C6\05\00\00\84\05\00\00O\F0\00\0BO\F0\00\0E\02\BCjF\04\B4\01\B4\DF\F8$\A0\08\A3\9AD\DF\F8 \C0Z\F8\0C\C0M\F8\04\CD\06KZ\F8\030\06HZ\F8\00\00\FF\F7T\EF\FF\F7X\EFD\16\00\00\E0\FF\FF\FF\E4\FF\FF\FF\E8\FF\FF\FF\140\9F\E5\14 \9F\E5\030\8F\E0\02 \93\E7\00\00R\E3\1E\FF/\01\A3\FF\FF\EA$\16\00\00\EC\FF\FF\FF\07K\08H{D\08JxD\033\1B\1AzD\06+\03\D9\05K\D3X\03\B1\18GpG\00\BF\E0\15\00\00\DC\15\00\00\FE\15\00\00\F0\FF\FF\FF\08I\09HyD\09KxD\09\1A{D\89\10\01\EB\D1qI\10\03\D0\05J\9BX\03\B1\18GpG\00\BF\B0\15\00\00\AC\15\00\00\D0\15\00\00\F4\FF\FF\FF\08\B5\0AK\0AJ{DzD\1Bxk\B9\09K\D3X#\B1\08K{D\18h\FF\F7\0A\EF\FF\F7\BD\FF\06K\01\22{D\1Ap\08\BD\CE\15\00\00\A0\15\00\00\F8\FF\FF\FFb\15\00\00\AE\15\00\00\07H\08\B5xD\02h\06K{D\12\B9\BD\E8\08@\BB\E7\04J\9BX\00+\F8\D0\98G\F6\E78\15\00\00^\15\00\00\FC\FF\FF\FF\82\B00\B4\82\B0\02\AC\05\93\04\E9\06\00\06\99\01\9D\00\9A)DA`\13D\03`\02\B00\BC\02\B0pG\82\B00\B4\82\B0\02\AC\06\9D\04\E9\06\00\01\99\00\9A\05\93I\1B\D3\1AA`\03`\02\B00\BC\02\B0pG\82\B0\F0\B4\82\B0\02\AC\07\93\04\E9\06\00\00\9C\08\9A\01\9E\04\FB\03\F7\04\FB\02\F4\06\FB\03A\06\FB\12rA`\02`\02\B0\F0\BC\02\B0pG\82\B0-\E9\F0C\83\B0\02\AD\80F\0C\9C\1FF\05\E9\06\00\01\9D\04\FB\04\F6\DD\F8\00\90\03\FB\03f\0B\93\05\FB\04\F0\09\FB\03\001F\00\F0\11\F8\05\FB\07\F51F\C8\F8\00\00\09\FB\14P\00\F0\08\F8\C8\F8\04\00@F\03\B0\BD\E8\F0C\02\B0pG\00)\00\F0>\81\80\EA\01\0CH\BFIBJ\1E\00\F0\1F\81\03\00H\BFCB\8BB@\F2\1E\81\11B\00\F0#\81\B3\FA\83\F2\B1\FA\81\F0\A0\EB\02\02\C2\F1\1F\02\04\A0\00\EB\02\12O\F0\00\00\97F\00\BF\AF\F3\00\80\B3\EB\C1\7F\00\BF@\EB\00\00(\BF\A3\EB\C1s\B3\EB\81\7F\00\BF@\EB\00\00(\BF\A3\EB\81s\B3\EBA\7F\00\BF@\EB\00\00(\BF\A3\EBAs\B3\EB\01\7F\00\BF@\EB\00\00(\BF\A3\EB\01s\B3\EB\C1o\00\BF@\EB\00\00(\BF\A3\EB\C1c\B3\EB\81o\00\BF@\EB\00\00(\BF\A3\EB\81c\B3\EBAo\00\BF@\EB\00\00(\BF\A3\EBAc\B3\EB\01o\00\BF@\EB\00\00(\BF\A3\EB\01c\B3\EB\C1_\00\BF@\EB\00\00(\BF\A3\EB\C1S\B3\EB\81_\00\BF@\EB\00\00(\BF\A3\EB\81S\B3\EBA_\00\BF@\EB\00\00(\BF\A3\EBAS\B3\EB\01_\00\BF@\EB\00\00(\BF\A3\EB\01S\B3\EB\C1O\00\BF@\EB\00\00(\BF\A3\EB\C1C\B3\EB\81O\00\BF@\EB\00\00(\BF\A3\EB\81C\B3\EBAO\00\BF@\EB\00\00(\BF\A3\EBAC\B3\EB\01O\00\BF@\EB\00\00(\BF\A3\EB\01C\B3\EB\C1?\00\BF@\EB\00\00(\BF\A3\EB\C13\B3\EB\81?\00\BF@\EB\00\00(\BF\A3\EB\813\B3\EBA?\00\BF@\EB\00\00(\BF\A3\EBA3\B3\EB\01?\00\BF@\EB\00\00(\BF\A3\EB\013\B3\EB\C1/\00\BF@\EB\00\00(\BF\A3\EB\C1#\B3\EB\81/\00\BF@\EB\00\00(\BF\A3\EB\81#\B3\EBA/\00\BF@\EB\00\00(\BF\A3\EBA#\B3\EB\01/\00\BF@\EB\00\00(\BF\A3\EB\01#\B3\EB\C1\1F\00\BF@\EB\00\00(\BF\A3\EB\C1\13\B3\EB\81\1F\00\BF@\EB\00\00(\BF\A3\EB\81\13\B3\EBA\1F\00\BF@\EB\00\00(\BF\A3\EBA\13\B3\EB\01\1F\00\BF@\EB\00\00(\BF\A3\EB\01\13\B3\EB\C1\0F\00\BF@\EB\00\00(\BF\A3\EB\C1\03\B3\EB\81\0F\00\BF@\EB\00\00(\BF\A3\EB\81\03\B3\EBA\0F\00\BF@\EB\00\00(\BF\A3\EBA\03\B3\EB\01\0F\00\BF@\EB\00\00(\BF\A3\EB\01\03\BC\F1\00\0FH\BF@BpG\9C\EA\00\0FH\BF@BpG8\BF\00 \04\BFO\EA\ECp@\F0\01\00pG\B1\FA\81\F2\C2\F1\1F\02\BC\F1\00\0F#\FA\02\F0H\BF@BpG\00(\C8\BFo\F0\00@\B8\BFO\F0\00@\00\F0\0E\B8\00)\F4\D0-\E9\03@\FF\F7\B3\FE\BD\E8\06@\02\FB\00\F3\A1\EB\03\01pG\00\BF\02\B5O\F0\08\00\FF\F78\ED\02\BD-\E9\F8C\07F\0CN\88F\0CM\91F~D\FF\F7\F2\EC}Dv\1B\B6\10\0A\D0\04=\00$\014U\F8\04?8FAFJF\98G\B4B\F6\D1\BD\E8\F8\83\00\BF\86\11\00\00|\11\00\00pG\00\BF" }>, %struct.__jove__fini <{ [8 x i8] c"\08@-\E9\08\80\BD\E8" }>, %struct.__jove__rodata <{ [52 x i8] c"\01\00\02\00usage: complex-num w x [+-*/] y z\00\00\00%li + %lii\0A\00" }>, %struct.__jove__ARM_exidx <{ [8 x i8] c"\BC\FA\FF\7F\01\00\00\00" }>, %struct.__jove__eh_frame zeroinitializer, %struct.__jove__eh_frame_hdr <{ [8 x i8] c"\01\1B\FF\FF\F8\FF\FF\FF" }>, [4096 x i8] zeroinitializer, %struct.__jove__dynamic <{ [240 x i8] c"\03\00\00\00\CC\1B\00\00\02\00\00\00@\00\00\00\17\00\00\00\CC\03\00\00\14\00\00\00\11\00\00\00\11\00\00\00t\03\00\00\12\00\00\00X\00\00\00\13\00\00\00\08\00\00\00\FA\FF\FFo\06\00\00\00\15\00\00\00\00\00\00\00\06\00\00\00\B4\01\00\00\0B\00\00\00\10\00\00\00\05\00\00\00t\02\00\00\0A\00\00\00\AE\00\00\00\F5\FE\FFo$\03\00\00\01\00\00\00\11\00\00\00\0C\00\00\00\0C\04\00\00\0D\00\00\00X\0A\00\00\1A\00\00\00\A4\1B\00\00\1C\00\00\00\04\00\00\00\19\00\00\00\A8\1B\00\00\1B\00\00\00\04\00\00\00\F0\FF\FFo<\03\00\00\FE\FF\FFoT\03\00\00\FF\FF\FFo\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" }>, %struct.__jove__data <{ [4 x i8] zeroinitializer, i32* bitcast (i32** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 23, i32 1) to i32*) }>, %struct.__jove__jcr zeroinitializer, %struct.__jove__fini_array <{ i32* bitcast (%struct.__jove__fini_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 25) to i32*) }>, %struct.__jove__init_array <{ i32* bitcast (%struct.__jove__init_array* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 26) to i32*) }>, %struct.__jove__got <{ i32* bitcast (%struct.__jove__got* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 27) to i32*), i32* bitcast (i32** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 27, i32 1) to i32*), i32* bitcast (i32** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 27, i32 2) to i32*), void ()* @__gmon_start__, void ()* @_ITM_deregisterTMCloneTable, void ()* @_ITM_registerTMCloneTable, void ()* @__cxa_finalize, void ()* @_Jv_RegisterClasses, [12 x i8] zeroinitializer, void ()* @__libc_start_main, void ()* @abort, void ()* @__gmon_start__, void ()* @__cxa_finalize, void ()* @puts, void ()* @strtol, void ()* @printf, void ()* @raise }>, %struct.__jove__bss zeroinitializer }>, align 4096

declare extern_weak void @__gmon_start__()

declare extern_weak void @_ITM_deregisterTMCloneTable()

declare extern_weak void @_ITM_registerTMCloneTable()

declare extern_weak void @__cxa_finalize()

declare extern_weak void @_Jv_RegisterClasses()

declare void @__libc_start_main()

declare void @abort()

declare void @puts()

declare void @strtol()

declare void @printf()

declare void @raise()

; Function Attrs: noinline
define internal void @"0x45c"() local_unnamed_addr #0 {
"0x45c":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 13) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @puts to i32), i32 -2) to void ()*))
  ret void
}

; Function Attrs: noinline
define internal void @"0x468"() local_unnamed_addr #0 {
"0x468":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 14) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @strtol to i32), i32 -2) to void ()*))
  ret void
}

; Function Attrs: noinline
define internal void @"0x480"() local_unnamed_addr #0 {
"0x480":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 16) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @raise to i32), i32 -2) to void ()*))
  ret void
}

; Function Attrs: noinline
define internal void @"0x450"() local_unnamed_addr #0 {
"0x450":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 12) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @__cxa_finalize to i32), i32 -2) to void ()*))
  ret void
}

; Function Attrs: noinline
define internal void @"0x438"() local_unnamed_addr #0 {
"0x438":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 10) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @abort to i32), i32 -2) to void ()*))
  ret void
}

; Function Attrs: noinline
define internal void @"0x42c"() local_unnamed_addr #0 {
"0x42c":
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 9) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @__libc_start_main to i32), i32 -2) to void ()*))
  ret void
}

; Function Attrs: noinline
define void @_init(i32 %r3) local_unnamed_addr #0 {
"0x40c":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_1, -8
  %1 = inttoptr i32 %0 to i32*
  store i32 %r3, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_1, -4
  %3 = inttoptr i32 %2 to i32*
  store i32 %r14_2, i32* %3, align 4, !noalias !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  tail call void @call_weak_fn()
  %r13_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %4 = inttoptr i32 %r13_3 to i32*
  %5 = load i32, i32* %4, align 4, !noalias !0
  %6 = add i32 %r13_3, 4
  %7 = inttoptr i32 %6 to i32*
  %8 = load i32, i32* %7, align 4, !noalias !0
  %9 = and i32 %8, 1
  store i32 %9, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %10 = add i32 %r13_3, 8
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  ret void
}

; Function Attrs: noinline
define internal { i32, i32 } @"0x75e"(i32 %r0, i32 %r1) local_unnamed_addr #0 {
"0x75e":
  %r14_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %NF_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  %0 = xor i32 %r1, %r0
  %1 = icmp sgt i32 %NF_2, -1
  %2 = sub i32 0, %r1
  %r1. = select i1 %1, i32 %r1, i32 %2
  %3 = add i32 %r1., -1
  %4 = icmp eq i32 %3, 0
  br i1 %4, label %"0x9aa", label %"0x76c"

"0x9aa":                                          ; preds = %"0x75e"
  %5 = and i32 %r1., -2
  %6 = icmp ne i32 %r1, 0
  %7 = zext i1 %6 to i32
  %8 = icmp sgt i32 %r1, -1
  %9 = sub i32 0, %r0
  %r0. = select i1 %8, i32 %r0, i32 %9
  %10 = and i32 %r14_1, 1
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %11 = insertvalue { i32, i32 } undef, i32 %r0., 0
  %12 = insertvalue { i32, i32 } %11, i32 %r1., 1
  ret { i32, i32 } %12

"0x76c":                                          ; preds = %"0x75e"
  %13 = icmp sgt i32 %r0, -1
  %14 = sub i32 0, %r0
  %r0.24 = select i1 %13, i32 %r0, i32 %14
  %15 = sub i32 %r0.24, %r1.
  %16 = icmp uge i32 %r0.24, %r1.
  %17 = zext i1 %16 to i32
  %18 = xor i32 %15, %r0.24
  %19 = xor i32 %r1., %r0.24
  %20 = and i32 %18, %19
  %21 = icmp ne i32 %15, 0
  %22 = and i1 %16, %21
  br i1 %22, label %"0x778", label %l39

"0x778":                                          ; preds = %"0x76c"
  %23 = and i32 %3, %r1.
  %24 = icmp eq i32 %23, 0
  br i1 %24, label %"0x9c4", label %"0x77e"

"0x9c4":                                          ; preds = %"0x778"
  %25 = tail call i32 @helper_clz(i32 %r1.)
  %26 = sub i32 31, %25
  %27 = and i32 %26, 224
  %28 = icmp ult i32 %27, 32
  %29 = select i1 %28, i32 %r0.24, i32 0
  %30 = and i32 %26, 31
  %31 = lshr i32 %29, %30
  %32 = icmp sgt i32 %0, -1
  %33 = sub i32 0, %31
  %.25 = select i1 %32, i32 %31, i32 %33
  %34 = and i32 %r14_1, 1
  store i32 %34, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %26, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %35 = insertvalue { i32, i32 } undef, i32 %.25, 0
  %36 = insertvalue { i32, i32 } %35, i32 %r1., 1
  ret { i32, i32 } %36

"0x77e":                                          ; preds = %"0x778"
  %37 = tail call i32 @helper_clz(i32 %r0.24)
  %38 = tail call i32 @helper_clz(i32 %r1.)
  %39 = sub i32 %37, %38
  %40 = shl i32 %39, 4
  %41 = add i32 %40, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1280) to i32)
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %r1., i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 %41, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %23, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %23, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %42 = inttoptr i32 %41 to void ()*
  tail call void @__jove_indirect_jump(void ()* %42)
  ret { i32, i32 } undef

l39:                                              ; preds = %"0x76c"
  %r0_.1 = select i1 %16, i32 %r0, i32 0
  %43 = icmp eq i32 %15, 0
  %44 = ashr i32 %0, 31
  %45 = or i32 %44, 1
  %..r0_.1 = select i1 %43, i32 %45, i32 %r0_.1
  %46 = and i32 %r14_1, 1
  store i32 %46, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %3, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %15, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %15, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %47 = insertvalue { i32, i32 } undef, i32 %..r0_.1, 0
  %48 = insertvalue { i32, i32 } %47, i32 %r1., 1
  ret { i32, i32 } %48
}

; Function Attrs: noinline
define internal { i32, i32 } @register_tm_clones() local_unnamed_addr #0 {
"0x5ec":
  %r14_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 384) to i32*), align 4, !noalias !0
  %1 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 388) to i32*), align 4, !noalias !0
  %2 = add i32 %0, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 356) to i32)
  %3 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 392) to i32*), align 4, !noalias !0
  %4 = add i32 %1, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 360) to i32)
  %5 = sub i32 %2, %4
  %6 = xor i32 %5, %2
  %7 = xor i32 %4, %2
  %8 = and i32 %6, %7
  %9 = add i32 %3, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 364) to i32)
  %10 = ashr i32 %5, 2
  %11 = lshr i32 %10, 31
  %12 = add nsw i32 %11, %10
  %13 = and i32 %12, 1
  %14 = ashr i32 %12, 1
  %15 = icmp eq i32 %14, 0
  br i1 %15, label %"0x60c", label %"0x604"

"0x60c":                                          ; preds = %"0x604", %"0x5ec"
  %r3_.0 = phi i32 [ %9, %"0x5ec" ], [ 0, %"0x604" ]
  %r2_.0 = phi i32 [ undef, %"0x5ec" ], [ %19, %"0x604" ]
  %16 = and i32 %r14_1, 1
  store i32 %16, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %r2_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r3_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %8, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %17 = insertvalue { i32, i32 } undef, i32 %4, 0
  %18 = insertvalue { i32, i32 } %17, i32 %14, 1
  ret { i32, i32 } %18

"0x604":                                          ; preds = %"0x5ec"
  %19 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 396) to i32*), align 4, !noalias !0
  %20 = add i32 %19, %9
  %21 = inttoptr i32 %20 to i32*
  %22 = load i32, i32* %21, align 4, !noalias !0
  %23 = icmp eq i32 %22, 0
  br i1 %23, label %"0x60c", label %"0x60a"

"0x60a":                                          ; preds = %"0x604"
  %24 = and i32 %22, 1
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %25 = and i32 %22, -2
  store i32 %4, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 %19, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %22, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %8, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %26 = inttoptr i32 %25 to void ()*
  tail call void @__jove_indirect_jump(void ()* %26)
  ret { i32, i32 } undef
}

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_add(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #1 {
"0x68c":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %r13_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_3, -16
  %1 = inttoptr i32 %0 to i32*
  store i32 %r4_1, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_3, -12
  %3 = inttoptr i32 %2 to i32*
  store i32 %r5_2, i32* %3, align 4, !noalias !0
  %4 = add i32 %r13_3, -24
  %5 = add i32 %r13_3, -4
  %6 = inttoptr i32 %5 to i32*
  store i32 %r3, i32* %6, align 4, !noalias !0
  %7 = inttoptr i32 %4 to i32*
  store i32 %r1, i32* %7, align 4, !noalias !0
  %8 = add i32 %r13_3, -20
  %9 = inttoptr i32 %8 to i32*
  store i32 %r2, i32* %9, align 4, !noalias !0
  %10 = inttoptr i32 %r13_3 to i32*
  %11 = load i32, i32* %10, align 4, !noalias !0
  %12 = load i32, i32* %7, align 4, !noalias !0
  %13 = add i32 %11, %r2
  %14 = add i32 %r0, 4
  %15 = inttoptr i32 %14 to i32*
  store i32 %13, i32* %15, align 4, !noalias !0
  %16 = add i32 %12, %r3
  %17 = inttoptr i32 %r0 to i32*
  store i32 %16, i32* %17, align 4, !noalias !0
  %18 = load i32, i32* %1, align 4, !noalias !0
  %19 = load i32, i32* %3, align 4, !noalias !0
  %20 = and i32 %r14_4, 1
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %12, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %16, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %18, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %19, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %21 = insertvalue { i32 } undef, i32 %13, 0
  ret { i32 } %21
}

; Function Attrs: noinline
define internal { i32, i32 } @__aeabi_idiv(i32 %r0, i32 %r1) local_unnamed_addr #0 {
"0x758":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = icmp eq i32 %r1, 0
  br i1 %0, label %"0xa08", label %"0x75e"

"0xa08":                                          ; preds = %"0x758"
  %1 = add i32 %r13_1, -8
  %2 = inttoptr i32 %1 to i32*
  store i32 0, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_1, -4
  %4 = inttoptr i32 %3 to i32*
  store i32 %r14_2, i32* %4, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 8, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x480"()
  %r13_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %5 = inttoptr i32 %r13_8 to i32*
  %6 = load i32, i32* %5, align 4, !noalias !0
  %7 = add i32 %r13_8, 4
  %8 = inttoptr i32 %7 to i32*
  %9 = load i32, i32* %8, align 4, !noalias !0
  %10 = and i32 %9, 1
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %11 = add i32 %r13_8, 8
  store i32 %11, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %12 = insertvalue { i32, i32 } { i32 8, i32 undef }, i32 %6, 1
  ret { i32, i32 } %12

"0x75e":                                          ; preds = %"0x758"
  %13 = xor i32 %r1, %r0
  %14 = icmp sgt i32 %r1, -1
  %15 = sub i32 0, %r1
  %r1. = select i1 %14, i32 %r1, i32 %15
  %16 = add i32 %r1., -1
  %17 = icmp eq i32 %16, 0
  br i1 %17, label %"0x9aa", label %"0x76c"

"0x9aa":                                          ; preds = %"0x75e"
  %18 = and i32 %r1., -2
  %19 = sub i32 0, %r0
  %r0. = select i1 %14, i32 %r0, i32 %19
  %20 = and i32 %r14_2, 1
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %18, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %21 = insertvalue { i32, i32 } undef, i32 %r0., 0
  %22 = insertvalue { i32, i32 } %21, i32 %r1., 1
  ret { i32, i32 } %22

"0x76c":                                          ; preds = %"0x75e"
  %23 = icmp sgt i32 %r0, -1
  %24 = sub i32 0, %r0
  %r0.39 = select i1 %23, i32 %r0, i32 %24
  %25 = sub i32 %r0.39, %r1.
  %26 = icmp uge i32 %r0.39, %r1.
  %27 = zext i1 %26 to i32
  %28 = xor i32 %25, %r0.39
  %29 = xor i32 %r1., %r0.39
  %30 = and i32 %28, %29
  %31 = icmp ne i32 %25, 0
  %32 = and i1 %26, %31
  br i1 %32, label %"0x778", label %l324

"0x778":                                          ; preds = %"0x76c"
  %33 = and i32 %16, %r1.
  %34 = icmp eq i32 %33, 0
  br i1 %34, label %"0x9c4", label %"0x77e"

"0x9c4":                                          ; preds = %"0x778"
  %35 = tail call i32 @helper_clz(i32 %r1.)
  %36 = sub i32 31, %35
  %37 = and i32 %36, 224
  %38 = icmp ult i32 %37, 32
  %39 = select i1 %38, i32 %r0.39, i32 0
  %40 = and i32 %36, 31
  %41 = lshr i32 %39, %40
  %42 = icmp sgt i32 %13, -1
  %43 = sub i32 0, %41
  %.41 = select i1 %42, i32 %41, i32 %43
  %44 = and i32 %r14_2, 1
  store i32 %44, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %36, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %45 = insertvalue { i32, i32 } undef, i32 %.41, 0
  %46 = insertvalue { i32, i32 } %45, i32 %r1., 1
  ret { i32, i32 } %46

"0x77e":                                          ; preds = %"0x778"
  %47 = tail call i32 @helper_clz(i32 %r0.39)
  %48 = tail call i32 @helper_clz(i32 %r1.)
  %49 = sub i32 %47, %48
  %50 = shl i32 %49, 4
  %51 = add i32 %50, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1280) to i32)
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %r1., i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 %51, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %33, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %33, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %52 = inttoptr i32 %51 to void ()*
  tail call void @__jove_indirect_jump(void ()* %52)
  ret { i32, i32 } undef

l324:                                             ; preds = %"0x76c"
  %r0_.1 = select i1 %26, i32 %r0, i32 0
  %53 = icmp eq i32 %25, 0
  %54 = ashr i32 %13, 31
  %55 = or i32 %54, 1
  %..r0_.1 = select i1 %53, i32 %55, i32 %r0_.1
  %56 = and i32 %r14_2, 1
  store i32 %56, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %16, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %25, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %25, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %57 = insertvalue { i32, i32 } undef, i32 %..r0_.1, 0
  %58 = insertvalue { i32, i32 } %57, i32 %r1., 1
  ret { i32, i32 } %58
}

; Function Attrs: noinline
define internal void @__do_global_dtors_aux(i32 %r3) local_unnamed_addr #0 {
"0x620":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_1, -8
  %1 = inttoptr i32 %0 to i32*
  store i32 %r3, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_1, -4
  %3 = inttoptr i32 %2 to i32*
  store i32 %r14_2, i32* %3, align 4, !noalias !0
  %4 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 444) to i32*), align 4, !noalias !0
  %5 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 448) to i32*), align 4, !noalias !0
  %6 = add i32 %4, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 410) to i32)
  %7 = add i32 %5, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 412) to i32)
  %8 = inttoptr i32 %6 to i32*
  %9 = load i32, i32* %8, align 4, !noalias !0
  %not. = icmp eq i32 %9, 0
  br i1 %not., label %"0x62e", label %"0x64a"

"0x64a":                                          ; preds = %"0x620"
  %10 = load i32, i32* %1, align 4, !noalias !0
  %11 = and i32 %r14_2, 1
  store i32 %11, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  ret void

"0x62e":                                          ; preds = %"0x620"
  %12 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 452) to i32*), align 4, !noalias !0
  %13 = add i32 %12, %7
  %14 = inttoptr i32 %13 to i32*
  %15 = load i32, i32* %14, align 4, !noalias !0
  %16 = icmp eq i32 %15, 0
  br i1 %16, label %"0x63e.exit", label %"0x634"

"0x63e.exit":                                     ; preds = %"0x634", %"0x62e"
  %r13_.0 = phi i32 [ %0, %"0x62e" ], [ %r13_14, %"0x634" ]
  %r3_.0 = phi i32 [ 0, %"0x62e" ], [ %29, %"0x634" ]
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r3_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %r13_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %17 = tail call { i32 } @deregister_tm_clones()
  %r0_returned = extractvalue { i32 } %17, 0
  store i32 %r0_returned, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  %r13_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %18 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 460) to i32*), align 4, !noalias !0
  %19 = add i32 %18, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 442) to i32)
  %20 = inttoptr i32 %19 to i32*
  store i32 1, i32* %20, align 4, !noalias !0
  %21 = inttoptr i32 %r13_8 to i32*
  %22 = load i32, i32* %21, align 4, !noalias !0
  %23 = add i32 %r13_8, 4
  %24 = inttoptr i32 %23 to i32*
  %25 = load i32, i32* %24, align 4, !noalias !0
  %26 = and i32 %25, 1
  store i32 %26, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %27 = add i32 %r13_8, 8
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %22, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  ret void

"0x634":                                          ; preds = %"0x62e"
  %28 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 456) to i32*), align 4, !noalias !0
  %29 = add i32 %28, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 426) to i32)
  %30 = inttoptr i32 %29 to i32*
  %31 = load i32, i32* %30, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %31, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  tail call void @"0x450"()
  %r13_14 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  br label %"0x63e.exit"
}

; Function Attrs: noinline
define void @call_weak_fn() local_unnamed_addr #0 {
"0x598":
  %0 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 292) to i32*), align 4, !noalias !0
  %1 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 296) to i32*), align 4, !noalias !0
  %2 = add i32 %0, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 280) to i32)
  %3 = add i32 %2, %1
  %4 = inttoptr i32 %3 to i32*
  %5 = load i32, i32* %4, align 4, !noalias !0
  %6 = icmp eq i32 %5, 0
  br i1 %6, label %l1, label %"0x444"

"0x444":                                          ; preds = %l1, %"0x598"
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 ptrtoint (void ()** getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 27, i32 11) to i32), i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @__jove_indirect_jump(void ()* inttoptr (i32 and (i32 ptrtoint (void ()* @__gmon_start__ to i32), i32 -2) to void ()*))
  ret void

l1:                                               ; preds = %"0x598"
  %r14_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %7 = and i32 %r14_1, 1
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  br label %"0x444"
}

; Function Attrs: noinline noreturn
define internal void @_start(i32 %r0) local_unnamed_addr #2 {
"0x550":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %0 = inttoptr i32 %r13_1 to i32*
  %1 = load i32, i32* %0, align 4, !noalias !0
  %2 = add i32 %r13_1, 4
  store i32 %2, i32* %0, align 4, !noalias !0
  %3 = add i32 %r13_1, -4
  %4 = inttoptr i32 %3 to i32*
  store i32 %r0, i32* %4, align 4, !noalias !0
  %5 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 248) to i32*), align 4, !noalias !0
  %6 = add i32 %5, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 248) to i32)
  %7 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 252) to i32*), align 4, !noalias !0
  %8 = add i32 %6, %7
  %9 = inttoptr i32 %8 to i32*
  %10 = load i32, i32* %9, align 4, !noalias !0
  %11 = add i32 %r13_1, -8
  %12 = inttoptr i32 %11 to i32*
  store i32 %10, i32* %12, align 4, !noalias !0
  %13 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 256) to i32*), align 4, !noalias !0
  %14 = add i32 %13, %6
  %15 = inttoptr i32 %14 to i32*
  %16 = load i32, i32* %15, align 4, !noalias !0
  %17 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 260) to i32*), align 4, !noalias !0
  %18 = add i32 %17, %6
  %19 = inttoptr i32 %18 to i32*
  %20 = load i32, i32* %19, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 %2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %16, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %6, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 10), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 11), align 4, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %11, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  tail call void @"0x42c"()
  unreachable
}

; Function Attrs: noinline
define internal { i32, i32 } @frame_dummy(i32 %r3) local_unnamed_addr #0 {
"0x660":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 496) to i32*), align 4, !noalias !0
  %1 = add i32 %r13_1, -8
  %2 = inttoptr i32 %1 to i32*
  store i32 %r3, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_1, -4
  %4 = inttoptr i32 %3 to i32*
  store i32 %r14_2, i32* %4, align 4, !noalias !0
  %5 = add i32 %0, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 472) to i32)
  %6 = inttoptr i32 %5 to i32*
  %7 = load i32, i32* %6, align 4, !noalias !0
  %not. = icmp eq i32 %7, 0
  br i1 %not., label %"0x66e", label %"0x674"

"0x674":                                          ; preds = %"0x660"
  %8 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 500) to i32*), align 4, !noalias !0
  %9 = add i32 %8, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 478) to i32)
  %10 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 504) to i32*), align 4, !noalias !0
  %11 = add i32 %9, %10
  %12 = inttoptr i32 %11 to i32*
  %13 = load i32, i32* %12, align 4, !noalias !0
  %14 = icmp eq i32 %13, 0
  br i1 %14, label %"0x66e", label %"0x67c"

"0x66e":                                          ; preds = %"0x67c", %"0x674", %"0x660"
  %15 = phi i32 [ %r14_2, %"0x674" ], [ %.pre, %"0x67c" ], [ %r14_2, %"0x660" ]
  %r2_.0 = phi i32 [ %10, %"0x674" ], [ %10, %"0x67c" ], [ 0, %"0x660" ]
  %16 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 384) to i32*), align 4, !noalias !0
  %17 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 388) to i32*), align 4, !noalias !0
  %18 = add i32 %16, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 356) to i32)
  %19 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 392) to i32*), align 4, !noalias !0
  %20 = add i32 %17, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 360) to i32)
  %21 = sub i32 %18, %20
  %22 = xor i32 %21, %18
  %23 = xor i32 %20, %18
  %24 = and i32 %22, %23
  %25 = add i32 %19, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 364) to i32)
  %26 = ashr i32 %21, 2
  %27 = lshr i32 %26, 31
  %28 = add nsw i32 %27, %26
  %29 = and i32 %28, 1
  %30 = ashr i32 %28, 1
  %31 = icmp eq i32 %30, 0
  br i1 %31, label %"0x60c", label %"0x604"

"0x60c":                                          ; preds = %"0x604", %"0x66e"
  %r3_.0 = phi i32 [ %25, %"0x66e" ], [ 0, %"0x604" ]
  %r2_.1 = phi i32 [ %r2_.0, %"0x66e" ], [ %35, %"0x604" ]
  %32 = and i32 %15, 1
  store i32 %32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %r2_.1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r3_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %r13_1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %33 = insertvalue { i32, i32 } undef, i32 %20, 0
  %34 = insertvalue { i32, i32 } %33, i32 %30, 1
  ret { i32, i32 } %34

"0x604":                                          ; preds = %"0x66e"
  %35 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 396) to i32*), align 4, !noalias !0
  %36 = add i32 %35, %25
  %37 = inttoptr i32 %36 to i32*
  %38 = load i32, i32* %37, align 4, !noalias !0
  %39 = icmp eq i32 %38, 0
  br i1 %39, label %"0x60c", label %"0x60a"

"0x60a":                                          ; preds = %"0x604"
  %40 = and i32 %38, 1
  store i32 %40, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %41 = and i32 %38, -2
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 %35, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %38, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %r13_1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %42 = inttoptr i32 %41 to void ()*
  tail call void @__jove_indirect_jump(void ()* %42)
  ret { i32, i32 } undef

"0x67c":                                          ; preds = %"0x674"
  %43 = and i32 %13, 1
  store i32 %43, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %44 = and i32 %13, -2
  %45 = inttoptr i32 %44 to void ()*
  tail call void @__jove_indirect_call(void ()* %45)
  %.pre = load i32, i32* %4, align 4, !noalias !0
  br label %"0x66e"
}

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_mul(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #1 {
"0x6d4":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %r6_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  %r7_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  %r13_5 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_6 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_5, -24
  %1 = inttoptr i32 %0 to i32*
  store i32 %r4_1, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_5, -20
  %3 = inttoptr i32 %2 to i32*
  store i32 %r5_2, i32* %3, align 4, !noalias !0
  %4 = add i32 %r13_5, -16
  %5 = inttoptr i32 %4 to i32*
  store i32 %r6_3, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_5, -12
  %7 = inttoptr i32 %6 to i32*
  store i32 %r7_4, i32* %7, align 4, !noalias !0
  %8 = add i32 %r13_5, -32
  %9 = add i32 %r13_5, -4
  %10 = inttoptr i32 %9 to i32*
  store i32 %r3, i32* %10, align 4, !noalias !0
  %11 = inttoptr i32 %8 to i32*
  store i32 %r1, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_5, -28
  %13 = inttoptr i32 %12 to i32*
  store i32 %r2, i32* %13, align 4, !noalias !0
  %14 = load i32, i32* %11, align 4, !noalias !0
  %15 = inttoptr i32 %r13_5 to i32*
  %16 = load i32, i32* %15, align 4, !noalias !0
  %17 = mul i32 %14, %r3
  %18 = mul i32 %16, %14
  %19 = mul i32 %r3, %r2
  %20 = add i32 %18, %19
  %21 = mul i32 %16, %r2
  %22 = sub i32 %17, %21
  %23 = add i32 %r0, 4
  %24 = inttoptr i32 %23 to i32*
  store i32 %20, i32* %24, align 4, !noalias !0
  %25 = inttoptr i32 %r0 to i32*
  store i32 %22, i32* %25, align 4, !noalias !0
  %26 = load i32, i32* %1, align 4, !noalias !0
  %27 = load i32, i32* %3, align 4, !noalias !0
  %28 = load i32, i32* %5, align 4, !noalias !0
  %29 = load i32, i32* %7, align 4, !noalias !0
  %30 = and i32 %r14_6, 1
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %22, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %26, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  store i32 %28, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  %31 = insertvalue { i32 } undef, i32 %20, 0
  ret { i32 } %31
}

; Function Attrs: noinline
define internal { i32 } @deregister_tm_clones() local_unnamed_addr #0 {
"0x5bc":
  %r14_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 332) to i32*), align 4, !noalias !0
  %1 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 336) to i32*), align 4, !noalias !0
  %2 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 340) to i32*), align 4, !noalias !0
  %3 = add i32 %1, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 312) to i32)
  %4 = add i32 %0, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 311) to i32)
  %.neg = sub i32 sub (i32 0, i32 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 312) to i32)), %1
  %5 = add i32 %4, %.neg
  %6 = add i32 %2, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 318) to i32)
  %7 = add i32 %5, -6
  %8 = icmp ugt i32 %5, 5
  %9 = zext i1 %8 to i32
  %10 = xor i32 %7, %5
  %11 = xor i32 %5, 6
  %12 = and i32 %10, %11
  %13 = icmp ne i32 %7, 0
  %14 = and i1 %8, %13
  br i1 %14, label %"0x5d0", label %"0x5d8"

"0x5d8":                                          ; preds = %"0x5d0", %"0x5bc"
  %r3_.0 = phi i32 [ %5, %"0x5bc" ], [ 0, %"0x5d0" ]
  %15 = and i32 %r14_1, 1
  store i32 %15, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %6, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r3_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %9, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %12, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %16 = insertvalue { i32 } undef, i32 %3, 0
  ret { i32 } %16

"0x5d0":                                          ; preds = %"0x5bc"
  %17 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 344) to i32*), align 4, !noalias !0
  %18 = add i32 %17, %6
  %19 = inttoptr i32 %18 to i32*
  %20 = load i32, i32* %19, align 4, !noalias !0
  %21 = icmp eq i32 %20, 0
  br i1 %21, label %"0x5d8", label %"0x5d6"

"0x5d6":                                          ; preds = %"0x5d0"
  %22 = and i32 %20, 1
  store i32 %22, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %23 = and i32 %20, -2
  store i32 %3, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %6, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %9, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %12, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %7, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %24 = inttoptr i32 %23 to void ()*
  tail call void @__jove_indirect_jump(void ()* %24)
  ret { i32 } undef
}

; Function Attrs: noinline
define internal { i32 } @__aeabi_idivmod(i32 %r0, i32 %r1) local_unnamed_addr #0 {
"0x9ec":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = icmp eq i32 %r1, 0
  br i1 %0, label %"0xa08", label %"0x9f0"

"0xa08":                                          ; preds = %"0x9ec"
  %1 = add i32 %r13_1, -8
  %2 = inttoptr i32 %1 to i32*
  store i32 0, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_1, -4
  %4 = inttoptr i32 %3 to i32*
  store i32 %r14_2, i32* %4, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 8, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x480"()
  %r13_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %5 = inttoptr i32 %r13_8 to i32*
  %6 = load i32, i32* %5, align 4, !noalias !0
  %7 = add i32 %r13_8, 4
  %8 = inttoptr i32 %7 to i32*
  %9 = load i32, i32* %8, align 4, !noalias !0
  %10 = and i32 %9, 1
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %11 = add i32 %r13_8, 8
  store i32 %11, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %12 = insertvalue { i32 } undef, i32 %6, 0
  ret { i32 } %12

"0x9f0":                                          ; preds = %"0x9ec"
  %13 = add i32 %r13_1, -12
  %14 = inttoptr i32 %13 to i32*
  store i32 %r0, i32* %14, align 4, !noalias !0
  %15 = add i32 %r13_1, -8
  %16 = inttoptr i32 %15 to i32*
  store i32 %r1, i32* %16, align 4, !noalias !0
  %17 = add i32 %r13_1, -4
  %18 = inttoptr i32 %17 to i32*
  store i32 %r14_2, i32* %18, align 4, !noalias !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %r0_14 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  %r1_15 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  %19 = tail call { i32, i32 } @"0x75e"(i32 %r0_14, i32 %r1_15)
  %r1_returned = extractvalue { i32, i32 } %19, 1
  store i32 %r1_returned, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  %r13_16 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r0_returned = extractvalue { i32, i32 } %19, 0
  %20 = inttoptr i32 %r13_16 to i32*
  %21 = load i32, i32* %20, align 4, !noalias !0
  %22 = add i32 %r13_16, 4
  %23 = inttoptr i32 %22 to i32*
  %24 = load i32, i32* %23, align 4, !noalias !0
  %25 = add i32 %r13_16, 8
  %26 = inttoptr i32 %25 to i32*
  %27 = load i32, i32* %26, align 4, !noalias !0
  %28 = mul i32 %24, %r0_returned
  %29 = and i32 %27, 1
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %30 = sub i32 %21, %28
  %31 = add i32 %r13_16, 12
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %28, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %31, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %32 = insertvalue { i32 } undef, i32 %30, 0
  ret { i32 } %32
}

; Function Attrs: noinline
define internal { i32 } @__aeabi_ldiv0(i32 %r1) local_unnamed_addr #0 {
"0xa08":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_1, -8
  %1 = inttoptr i32 %0 to i32*
  store i32 %r1, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_1, -4
  %3 = inttoptr i32 %2 to i32*
  store i32 %r14_2, i32* %3, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 8, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  tail call void @"0x480"()
  %r13_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %4 = inttoptr i32 %r13_3 to i32*
  %5 = load i32, i32* %4, align 4, !noalias !0
  %6 = add i32 %r13_3, 4
  %7 = inttoptr i32 %6 to i32*
  %8 = load i32, i32* %7, align 4, !noalias !0
  %9 = and i32 %8, 1
  store i32 %9, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %10 = add i32 %r13_3, 8
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %11 = insertvalue { i32 } undef, i32 %5, 0
  ret { i32 } %11
}

; Function Attrs: noinline norecurse nounwind
define internal void @__libc_csu_fini() local_unnamed_addr #1 {
"0xa54":
  %r14_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = and i32 %r14_1, 1
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  ret void
}

; Function Attrs: noinline
define internal void @__libc_csu_init(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
"0xa14":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %r6_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  %r7_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  %r8_5 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  %r9_6 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  %r13_7 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_7, -32
  %1 = inttoptr i32 %0 to i32*
  store i32 %r3, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_7, -28
  %3 = inttoptr i32 %2 to i32*
  store i32 %r4_1, i32* %3, align 4, !noalias !0
  %4 = add i32 %r13_7, -24
  %5 = inttoptr i32 %4 to i32*
  store i32 %r5_2, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_7, -20
  %7 = inttoptr i32 %6 to i32*
  store i32 %r6_3, i32* %7, align 4, !noalias !0
  %8 = add i32 %r13_7, -16
  %9 = inttoptr i32 %8 to i32*
  store i32 %r7_4, i32* %9, align 4, !noalias !0
  %10 = add i32 %r13_7, -12
  %11 = inttoptr i32 %10 to i32*
  store i32 %r8_5, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_7, -8
  %13 = inttoptr i32 %12 to i32*
  store i32 %r9_6, i32* %13, align 4, !noalias !0
  %14 = add i32 %r13_7, -4
  %15 = inttoptr i32 %14 to i32*
  store i32 %r14_8, i32* %15, align 4, !noalias !0
  %16 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1468) to i32*), align 4, !noalias !0
  %17 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1472) to i32*), align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %18 = add i32 %16, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1430) to i32)
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  store i32 %18, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  store i32 %r2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r3_9 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  tail call void @_init(i32 %r3_9)
  %r6_11 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  %r13_15 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r5_10 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %19 = add i32 %r5_10, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1436) to i32)
  %20 = sub i32 %r6_11, %19
  %21 = xor i32 %20, %r6_11
  %22 = xor i32 %19, %r6_11
  %23 = and i32 %21, %22
  %24 = lshr i32 %20, 1
  %25 = and i32 %24, 1
  %26 = ashr i32 %20, 2
  %27 = icmp eq i32 %26, 0
  br i1 %27, label %"0xa46", label %"0xa30"

"0xa46.loopexit":                                 ; preds = %"0xa34"
  br label %"0xa46"

"0xa46":                                          ; preds = %"0xa30", %"0xa46.loopexit", %"0xa14"
  %VF_.0 = phi i32 [ %23, %"0xa14" ], [ %63, %"0xa30" ], [ 0, %"0xa46.loopexit" ]
  %CF_.0 = phi i32 [ %25, %"0xa14" ], [ %60, %"0xa30" ], [ 1, %"0xa46.loopexit" ]
  %28 = inttoptr i32 %r13_15 to i32*
  %29 = load i32, i32* %28, align 4, !noalias !0
  %30 = add i32 %r13_15, 4
  %31 = inttoptr i32 %30 to i32*
  %32 = load i32, i32* %31, align 4, !noalias !0
  %33 = add i32 %r13_15, 8
  %34 = inttoptr i32 %33 to i32*
  %35 = load i32, i32* %34, align 4, !noalias !0
  %36 = add i32 %r13_15, 12
  %37 = inttoptr i32 %36 to i32*
  %38 = load i32, i32* %37, align 4, !noalias !0
  %39 = add i32 %r13_15, 16
  %40 = inttoptr i32 %39 to i32*
  %41 = load i32, i32* %40, align 4, !noalias !0
  %42 = add i32 %r13_15, 20
  %43 = inttoptr i32 %42 to i32*
  %44 = load i32, i32* %43, align 4, !noalias !0
  %45 = add i32 %r13_15, 24
  %46 = inttoptr i32 %45 to i32*
  %47 = load i32, i32* %46, align 4, !noalias !0
  %48 = add i32 %r13_15, 28
  %49 = inttoptr i32 %48 to i32*
  %50 = load i32, i32* %49, align 4, !noalias !0
  %51 = and i32 %50, 1
  store i32 %51, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %52 = add i32 %r13_15, 32
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %35, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  store i32 %38, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  store i32 %41, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  store i32 %44, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  store i32 %47, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  store i32 %52, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %CF_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %VF_.0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  ret void

"0xa30":                                          ; preds = %"0xa14"
  %53 = inttoptr i32 %19 to i32*
  %54 = load i32, i32* %53, align 4, !noalias !0
  %55 = and i32 %54, 1
  store i32 %55, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %56 = and i32 %54, -2
  %57 = inttoptr i32 %56 to void ()*
  tail call void @__jove_indirect_call(void ()* %57)
  %58 = sub nsw i32 1, %26
  %59 = icmp eq i32 %26, 1
  %60 = zext i1 %59 to i32
  %61 = xor i32 %58, 1
  %62 = xor i32 %26, 1
  %63 = and i32 %61, %62
  %not.34 = icmp eq i32 %58, 0
  br i1 %not.34, label %"0xa46", label %"0xa34.preheader"

"0xa34.preheader":                                ; preds = %"0xa30"
  br label %"0xa34"

"0xa34":                                          ; preds = %"0xa34", %"0xa34.preheader"
  %r4_.036 = phi i32 [ %69, %"0xa34" ], [ 1, %"0xa34.preheader" ]
  %r5_.035 = phi i32 [ %64, %"0xa34" ], [ %19, %"0xa34.preheader" ]
  %64 = add i32 %r5_.035, 4
  %65 = inttoptr i32 %64 to i32*
  %66 = load i32, i32* %65, align 4, !noalias !0
  %67 = and i32 %66, 1
  store i32 %67, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %68 = and i32 %66, -2
  %69 = add i32 %r4_.036, 1
  %70 = inttoptr i32 %68 to void ()*
  tail call void @__jove_indirect_call(void ()* %70)
  %exitcond = icmp eq i32 %69, %26
  br i1 %exitcond, label %"0xa46.loopexit", label %"0xa34"
}

; Function Attrs: noinline norecurse nounwind
define void @_fini(i32 %r3) local_unnamed_addr #1 {
"0xa58":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_1, -8
  %1 = inttoptr i32 %0 to i32*
  store i32 %r3, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_1, -4
  %3 = inttoptr i32 %2 to i32*
  store i32 %r14_2, i32* %3, align 4, !noalias !0
  %4 = load i32, i32* %1, align 4, !noalias !0
  %5 = and i32 %r14_2, 1
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %4, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  ret void
}

; Function Attrs: noinline
define internal { i32 } @main(i32 %r0, i32 %r1) local_unnamed_addr #0 {
"0x490":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r13_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r0, -6
  %1 = icmp ugt i32 %r0, 5
  %2 = zext i1 %1 to i32
  %3 = xor i32 %0, %r0
  %4 = xor i32 %r0, 6
  %5 = and i32 %3, %4
  %6 = add i32 %r13_2, -8
  %7 = inttoptr i32 %6 to i32*
  store i32 %r4_1, i32* %7, align 4, !noalias !0
  %8 = add i32 %r13_2, -4
  %9 = inttoptr i32 %8 to i32*
  store i32 %r14_3, i32* %9, align 4, !noalias !0
  %10 = add i32 %r13_2, -40
  %11 = icmp eq i32 %0, 0
  br i1 %11, label %"0x4a6", label %"0x498"

"0x4a6":                                          ; preds = %"0x490"
  %12 = add i32 %r1, 4
  %13 = inttoptr i32 %12 to i32*
  %14 = load i32, i32* %13, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x468"()
  %r13_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r4_7 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r0_6 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  %15 = add i32 %r13_8, 8
  %16 = inttoptr i32 %15 to i32*
  store i32 %r0_6, i32* %16, align 4, !noalias !0
  %17 = add i32 %r4_7, 8
  %18 = inttoptr i32 %17 to i32*
  %19 = load i32, i32* %18, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %19, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x468"()
  %r13_13 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r4_12 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r0_11 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  %20 = add i32 %r13_13, 12
  %21 = inttoptr i32 %20 to i32*
  store i32 %r0_11, i32* %21, align 4, !noalias !0
  %22 = add i32 %r4_12, 16
  %23 = inttoptr i32 %22 to i32*
  %24 = load i32, i32* %23, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x468"()
  %r13_18 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r4_17 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r0_16 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  %25 = add i32 %r13_18, 16
  %26 = inttoptr i32 %25 to i32*
  store i32 %r0_16, i32* %26, align 4, !noalias !0
  %27 = add i32 %r4_17, 20
  %28 = inttoptr i32 %27 to i32*
  %29 = load i32, i32* %28, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x468"()
  %r13_23 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r4_22 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r0_21 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  %30 = add i32 %r4_22, 12
  %31 = inttoptr i32 %30 to i32**
  %32 = load i32*, i32** %31, align 4, !noalias !0
  %33 = load i32, i32* %32, align 4, !noalias !0
  %34 = add i32 %33, -42
  %35 = add i32 %r13_23, 20
  %36 = inttoptr i32 %35 to i32*
  store i32 %r0_21, i32* %36, align 4, !noalias !0
  %37 = add i32 %33, -47
  %38 = icmp ugt i32 %34, 4
  %39 = zext i1 %38 to i32
  %40 = xor i32 %37, %34
  %41 = xor i32 %34, 5
  %42 = and i32 %40, %41
  %43 = icmp eq i32 %37, 0
  %not. = xor i1 %38, true
  %44 = or i1 %43, %not.
  br i1 %44, label %"0x4e2.exit", label %l127

"0x4e2.exit":                                     ; preds = %"0x4a6"
  %45 = add i32 %33, add (i32 ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 86) to i32), i32 -42)
  %46 = inttoptr i32 %45 to i32*
  %47 = load i32, i32* %46, align 4, !noalias !0
  %48 = shl i32 %47, 1
  %49 = add i32 %48, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 86) to i32)
  store i32 %34, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %37, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %42, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %37, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %50 = inttoptr i32 %49 to void ()*
  tail call void @__jove_indirect_jump(void ()* %50)
  ret { i32 } undef

"0x498":                                          ; preds = %"0x490"
  %51 = load i32, i32* bitcast (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 184) to i32*), align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %52 = add i32 %51, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 14) to i32)
  store i32 %52, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 0), align 4, !alias.scope !0
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x45c"()
  %r13_36 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %53 = add i32 %r13_36, 32
  %54 = inttoptr i32 %53 to i32*
  %55 = load i32, i32* %54, align 4, !noalias !0
  %56 = add i32 %r13_36, 36
  %57 = inttoptr i32 %56 to i32*
  %58 = load i32, i32* %57, align 4, !noalias !0
  %59 = and i32 %58, 1
  store i32 %59, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %60 = add i32 %r13_36, 40
  store i32 %55, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %60, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %5, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  ret { i32 } zeroinitializer

l127:                                             ; preds = %"0x4a6"
  %61 = add i32 %r13_23, 32
  %62 = inttoptr i32 %61 to i32*
  %63 = load i32, i32* %62, align 4, !noalias !0
  %64 = add i32 %r13_23, 36
  %65 = inttoptr i32 %64 to i32*
  %66 = load i32, i32* %65, align 4, !noalias !0
  %67 = and i32 %66, 1
  store i32 %67, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %68 = add i32 %r13_23, 40
  store i32 %34, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %63, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %68, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %42, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  ret { i32 } { i32 1 }
}

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_sub(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #1 {
"0x6b0":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %r13_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_3, -16
  %1 = inttoptr i32 %0 to i32*
  store i32 %r4_1, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_3, -12
  %3 = inttoptr i32 %2 to i32*
  store i32 %r5_2, i32* %3, align 4, !noalias !0
  %4 = add i32 %r13_3, -24
  %5 = inttoptr i32 %r13_3 to i32*
  %6 = load i32, i32* %5, align 4, !noalias !0
  %7 = inttoptr i32 %4 to i32*
  store i32 %r1, i32* %7, align 4, !noalias !0
  %8 = add i32 %r13_3, -20
  %9 = inttoptr i32 %8 to i32*
  store i32 %r2, i32* %9, align 4, !noalias !0
  %10 = load i32, i32* %7, align 4, !noalias !0
  %11 = add i32 %r13_3, -4
  %12 = inttoptr i32 %11 to i32*
  store i32 %r3, i32* %12, align 4, !noalias !0
  %13 = sub i32 %r2, %6
  %14 = sub i32 %10, %r3
  %15 = add i32 %r0, 4
  %16 = inttoptr i32 %15 to i32*
  store i32 %13, i32* %16, align 4, !noalias !0
  %17 = inttoptr i32 %r0 to i32*
  store i32 %14, i32* %17, align 4, !noalias !0
  %18 = load i32, i32* %1, align 4, !noalias !0
  %19 = load i32, i32* %3, align 4, !noalias !0
  %20 = and i32 %r14_4, 1
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %21 = xor i32 %14, %10
  %22 = xor i32 %10, %r3
  %23 = and i32 %21, %22
  %24 = icmp uge i32 %10, %r3
  %25 = zext i1 %24 to i32
  store i32 %10, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %18, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %19, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  store i32 %25, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %23, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %26 = insertvalue { i32 } undef, i32 %13, 0
  ret { i32 } %26
}

; Function Attrs: noinline
define internal { i32 } @cn_div(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
"0x704":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %r6_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  %r7_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  %r8_5 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  %r9_6 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  %r13_7 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r14_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %0 = add i32 %r13_7, -36
  %1 = inttoptr i32 %0 to i32*
  store i32 %r4_1, i32* %1, align 4, !noalias !0
  %2 = add i32 %r13_7, -32
  %3 = inttoptr i32 %2 to i32*
  store i32 %r5_2, i32* %3, align 4, !noalias !0
  %4 = add i32 %r13_7, -28
  %5 = inttoptr i32 %4 to i32*
  store i32 %r6_3, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_7, -24
  %7 = inttoptr i32 %6 to i32*
  store i32 %r7_4, i32* %7, align 4, !noalias !0
  %8 = add i32 %r13_7, -20
  %9 = inttoptr i32 %8 to i32*
  store i32 %r8_5, i32* %9, align 4, !noalias !0
  %10 = add i32 %r13_7, -16
  %11 = inttoptr i32 %10 to i32*
  store i32 %r9_6, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_7, -12
  %13 = inttoptr i32 %12 to i32*
  store i32 %r14_8, i32* %13, align 4, !noalias !0
  %14 = add i32 %r13_7, -48
  %15 = inttoptr i32 %r13_7 to i32*
  %16 = load i32, i32* %15, align 4, !noalias !0
  %17 = inttoptr i32 %14 to i32*
  store i32 %r1, i32* %17, align 4, !noalias !0
  %18 = add i32 %r13_7, -44
  %19 = inttoptr i32 %18 to i32*
  store i32 %r2, i32* %19, align 4, !noalias !0
  %20 = mul i32 %16, %16
  %21 = load i32, i32* %17, align 4, !noalias !0
  %22 = mul i32 %r3, %r3
  %23 = add i32 %20, %22
  %24 = add i32 %r13_7, -4
  %25 = inttoptr i32 %24 to i32*
  store i32 %r3, i32* %25, align 4, !noalias !0
  %26 = mul i32 %21, %r3
  %27 = mul i32 %16, %r2
  %28 = add i32 %26, %27
  store i32 %16, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %r2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  store i32 %23, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  store i32 %r3, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  store i32 %21, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %29 = tail call { i32, i32 } @__aeabi_idiv(i32 %28, i32 %23)
  %r1_returned = extractvalue { i32, i32 } %29, 1
  store i32 %r1_returned, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  %r6_11 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  %r9_14 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  %r8_1326 = load i32*, i32** bitcast (i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8) to i32**), align 4, !alias.scope !0
  %r7_12 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  %r5_10 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %r4_9 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  %r0_returned = extractvalue { i32, i32 } %29, 0
  %30 = mul i32 %r5_10, %r7_12
  store i32 %r0_returned, i32* %r8_1326, align 4, !noalias !0
  %31 = mul i32 %r4_9, %r9_14
  %32 = sub i32 %30, %31
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  %33 = tail call { i32, i32 } @__aeabi_idiv(i32 %32, i32 %r6_11)
  %r1_returned21 = extractvalue { i32, i32 } %33, 1
  store i32 %r1_returned21, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 1), align 4, !alias.scope !0
  %r8_22 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  %r13_23 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %r0_returned20 = extractvalue { i32, i32 } %33, 0
  %34 = add i32 %r8_22, 4
  %35 = inttoptr i32 %34 to i32*
  store i32 %r0_returned20, i32* %35, align 4, !noalias !0
  %36 = add i32 %r13_23, 12
  %37 = inttoptr i32 %36 to i32*
  %38 = load i32, i32* %37, align 4, !noalias !0
  %39 = add i32 %r13_23, 16
  %40 = inttoptr i32 %39 to i32*
  %41 = load i32, i32* %40, align 4, !noalias !0
  %42 = add i32 %r13_23, 20
  %43 = inttoptr i32 %42 to i32*
  %44 = load i32, i32* %43, align 4, !noalias !0
  %45 = add i32 %r13_23, 24
  %46 = inttoptr i32 %45 to i32*
  %47 = load i32, i32* %46, align 4, !noalias !0
  %48 = add i32 %r13_23, 28
  %49 = inttoptr i32 %48 to i32*
  %50 = load i32, i32* %49, align 4, !noalias !0
  %51 = add i32 %r13_23, 32
  %52 = inttoptr i32 %51 to i32*
  %53 = load i32, i32* %52, align 4, !noalias !0
  %54 = add i32 %r13_23, 36
  %55 = inttoptr i32 %54 to i32*
  %56 = load i32, i32* %55, align 4, !noalias !0
  %57 = and i32 %56, 1
  store i32 %57, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 18), align 4, !alias.scope !0
  %58 = add i32 %r13_23, 48
  store i32 %38, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 4), align 4, !alias.scope !0
  store i32 %41, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 5), align 4, !alias.scope !0
  store i32 %44, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 6), align 4, !alias.scope !0
  store i32 %47, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 7), align 4, !alias.scope !0
  store i32 %50, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 8), align 4, !alias.scope !0
  store i32 %53, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 9), align 4, !alias.scope !0
  store i32 %58, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 13), align 4, !alias.scope !0
  %59 = insertvalue { i32 } undef, i32 %r8_22, 0
  ret { i32 } %59
}

declare void @__jove_indirect_jump(void ()*) local_unnamed_addr

; Function Attrs: nounwind readnone
declare i32 @helper_clz(i32) local_unnamed_addr #3

declare void @__jove_indirect_call(void ()*) local_unnamed_addr

declare void @__jove_call(void ()*)

attributes #0 = { noinline }
attributes #1 = { noinline norecurse nounwind }
attributes #2 = { noinline noreturn }
attributes #3 = { nounwind readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="pentium4" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!0 = !{!1}
!1 = !{!"JoveScope", !2}
!2 = !{!"JoveDomain"}
```
# How to Build
```bash
export JOVE_SRC_DIR=/path/to/jove
git clone git@github.mit.edu:an23640/jove.git $JOVE_SRC_DIR
```
## Prerequisites (Linux)
* GNU parallel
* boost
* OCaml
* LLVM w/ ocaml bindings, clang, and lld (version >= 4.0)
* OCamlgraph
```bash
# on ArchLinux
yaourt -S parallel boost llvm clang llvm-ocaml boost lld lldb ocaml-ocamlgraph
```
## Build QEMU 2.6.2 (Linux)
```bash
# $JOVE_SRC_DIR must be set

export QEMU_SRC_DIR=/path/to/qemu
git clone https://github.com/qemu/qemu.git -b v2.6.2 $QEMU_SRC_DIR
cd $QEMU_SRC_DIR
patch -p1 < $JOVE_SRC_DIR/patches/qemu.patch
cd -
export QEMU_BUILD_DIR=/path/to/qemu/build/directory
mkdir -p $QEMU_BUILD_DIR
cd $QEMU_BUILD_DIR
CC=clang CXX=clang++ $QEMU_SRC_DIR/configure --python=$(which python2) --target-list=$(bits=$(${JOVE_SRC_DIR}/scripts/addrbits) ; if [ "${bits}" == "32" ]; then printf '%s' "arm-linux-user" ; fi ; if [ "${bits}" == "64" ]; then printf '%s' "x86_64-linux-user,aarch64-linux-user" ; fi) '--extra-cflags=-flto -fno-inline -fuse-ld=gold' --disable-werror --disable-gtk --disable-libnfs --disable-bzip2 --disable-numa --disable-lzo --disable-vhdx --disable-libssh2 --disable-seccomp --disable-opengl --disable-smartcard --disable-spice --disable-curses --disable-glusterfs --disable-rbd --disable-snappy --disable-tpm --disable-libusb --disable-nettle --disable-gnutls --disable-curl --disable-vnc --disable-kvm --disable-brlapi --disable-bluez --enable-tcg-interpreter --disable-fdt --disable-xfsctl --disable-pie --disable-docs --disable-vde --disable-gcrypt --disable-virglrenderer --disable-libiscsi --disable-usb-redir --disable-virtfs --disable-coroutine-pool --disable-archipelago --disable-rdma --disable-linux-aio --disable-netmap --disable-cap-ng --disable-attr --disable-vhost-net --disable-xen --disable-xen-pci-passthrough --disable-libssh2 --disable-slirp --disable-uuid --without-pixman --disable-tools --disable-system --enable-debug
make -j$(nproc)
```
## Building jove with `make(1)`
```bash
cd $JOVE_SRC_DIR
# $QEMU_SRC_DIR and $QEMU_BUILD_DIR must be set

# delete any existing build files
make clean
# must configure (once) after cleaning
make configure
# build it!
make -j$(nproc)
```
