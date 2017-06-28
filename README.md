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
1d20
  1d20
    note: invalid instruction @ 1d20
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
    note: unconditional jump
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
    note: unconditional jump
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
    note: unconditional jump
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
    note: unconditional jump
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
    note: unconditional jump
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
$ ../../scripts/viewbc complex-num.jv/bitcode/decompilation
```
#### LLVM
```llvm
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

; Function Attrs: noinline norecurse nounwind
define { i64, i64 } @cn_add(i64 %x0, i64 %x1, i64 %x2, i64 %x3) local_unnamed_addr #2 {
"0x93c":
  %sp_2 = load i64, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 1, i64 31), align 8, !alias.scope !0
  %0 = add i64 %sp_2, -48
  %1 = add i64 %sp_2, -32
  %2 = inttoptr i64 %1 to i64*
  store i64 %x0, i64* %2, align 4, !noalias !0
  %3 = add i64 %sp_2, -24
  %4 = inttoptr i64 %3 to i64*
  store i64 %x1, i64* %4, align 4, !noalias !0
  %5 = inttoptr i64 %0 to i64*
  store i64 %x2, i64* %5, align 4, !noalias !0
  %6 = add i64 %sp_2, -40
  %7 = inttoptr i64 %6 to i64*
  store i64 %x3, i64* %7, align 4, !noalias !0
  %8 = load i64, i64* %2, align 4, !noalias !0
  %9 = load i64, i64* %4, align 4
  %10 = load i64, i64* %5, align 4, !noalias !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 6), align 8, !alias.scope !0
  store i64 %x3, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 7), align 8, !alias.scope !0
  %11 = add i64 %10, %8
  store i64 %11, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 4), align 8, !alias.scope !0
  %12 = add i64 %9, %x3
  store i64 %12, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 5), align 8, !alias.scope !0
  %13 = add i64 %sp_2, -16
  %14 = add i64 %sp_2, -8
  %15 = inttoptr i64 %13 to i64*
  store i64 %11, i64* %15, align 4, !noalias !0
  %16 = inttoptr i64 %14 to i64*
  store i64 %12, i64* %16, align 4, !noalias !0
  %17 = load i64, i64* %15, align 4, !noalias !0
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
  store i64 %x0, i64* %2, align 4, !noalias !0
  %3 = add i64 %sp_2, -24
  %4 = inttoptr i64 %3 to i64*
  store i64 %x1, i64* %4, align 4, !noalias !0
  %5 = inttoptr i64 %0 to i64*
  store i64 %x2, i64* %5, align 4, !noalias !0
  %6 = add i64 %sp_2, -40
  %7 = inttoptr i64 %6 to i64*
  store i64 %x3, i64* %7, align 4, !noalias !0
  %8 = load i64, i64* %2, align 4, !noalias !0
  %9 = load i64, i64* %4, align 4
  %10 = load i64, i64* %5, align 4, !noalias !0
  store i64 %10, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 6), align 8, !alias.scope !0
  store i64 %x3, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 7), align 8, !alias.scope !0
  %11 = sub i64 %8, %10
  store i64 %11, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 4), align 8, !alias.scope !0
  %12 = sub i64 %9, %x3
  store i64 %12, i64* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 28, i32 0, i64 5), align 8, !alias.scope !0
  %13 = add i64 %sp_2, -16
  %14 = add i64 %sp_2, -8
  %15 = inttoptr i64 %13 to i64*
  store i64 %11, i64* %15, align 4, !noalias !0
  %16 = inttoptr i64 %14 to i64*
  store i64 %12, i64* %16, align 4, !noalias !0
  %17 = load i64, i64* %15, align 4, !noalias !0
  %18 = insertvalue { i64, i64 } undef, i64 %17, 0
  %19 = insertvalue { i64, i64 } %18, i64 %12, 1
  ret { i64, i64 } %19
}

; Function Attrs: noinline norecurse nounwind readnone
define { i64, i64, i64, i64, i64, i64, i64 } @cn_div(i64 %x0, i64 %x1, i64 %x2, i64 %x3) local_unnamed_addr #0 {
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
  %9 = icmp eq i64 %4, 0
  br i1 %9, label %helper_sdiv64.exit3, label %10

; <label>:10:                                     ; preds = %"0x9a4"
  %11 = icmp eq i64 %6, -9223372036854775808
  %12 = icmp eq i64 %4, -1
  %or.cond.i = and i1 %11, %12
  br i1 %or.cond.i, label %15, label %13

; <label>:13:                                     ; preds = %10
  %14 = sdiv i64 %6, %4
  br label %15

; <label>:15:                                     ; preds = %10, %13
  %.0.i.ph = phi i64 [ -9223372036854775808, %10 ], [ %14, %13 ]
  %16 = icmp eq i64 %8, -9223372036854775808
  %or.cond.i1 = and i1 %16, %12
  br i1 %or.cond.i1, label %helper_sdiv64.exit3, label %17

; <label>:17:                                     ; preds = %15
  %18 = sdiv i64 %8, %4
  br label %helper_sdiv64.exit3

helper_sdiv64.exit3:                              ; preds = %"0x9a4", %15, %17
  %.0.i5 = phi i64 [ %.0.i.ph, %17 ], [ %.0.i.ph, %15 ], [ 0, %"0x9a4" ]
  %.0.i2 = phi i64 [ %18, %17 ], [ -9223372036854775808, %15 ], [ 0, %"0x9a4" ]
  %19 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } undef, i64 %.0.i2, 0
  %20 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %19, i64 %.0.i5, 1
  %21 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %20, i64 %8, 2
  %22 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %21, i64 %6, 3
  %23 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %22, i64 %2, 4
  %24 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %23, i64 %1, 5
  %25 = insertvalue { i64, i64, i64, i64, i64, i64, i64 } %24, i64 %0, 6
  ret { i64, i64, i64, i64, i64, i64, i64 } %25
}
```
### x86_64
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

Translating x86_64 machine code to QEMU IR...

7e0
  7e0
    note: unconditional jump
  7ffd40e445f8
    note: no code @ 7ffd40e445f8
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
    note: unconditional jump
  5dd
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
  685
    note: unconditional jump
  68f
    note: direct call to 7d0
  69d
    note: unconditional jump
  649
    note: direct call to 590
  65b
    note: conditional jump to 65f and 685
  65f
    note: direct call to 7e0
  66d
    note: unconditional jump
  672
    note: direct call to 7c0
  680
    note: unconditional jump
7c0
  7c0
    note: return
6b0
  6b0
    note: indirect call
  6da
    note: unconditional jump
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
    note: unconditional jump
  7ffd40e44610
    note: no code @ 7ffd40e44610
  890
    note: direct call to 7ffd40e44610
558
  558
    note: conditional jump to 568 and 56a
  568
    note: indirect call
  56a
    note: unconditional jump
  1100000012
    note: no code @ 1100000012
800
  800
    note: return
720
  720
    note: conditional jump to 748 and 760
  748
    note: conditional jump to 754 and 760
  754
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
  760
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
6e0
  6e0
    note: conditional jump to 6f7 and 710
  6f7
    note: conditional jump to 703 and 710
  703
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
  710
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
8c4
  8c4
    note: unconditional jump
  7ffd40e44728
    note: no code @ 7ffd40e44728
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
    note: unconditional jump
  1
    note: no code @ 1
  7a8
    note: return
8c0
  8c0
    note: return
7b0
  7b0
    note: unconditional jump
  720
    note: conditional jump to 748 and 760
  748
    note: conditional jump to 754 and 760
  754
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
  760
    note: unconditional jump
  f1f0efee0e2d062f
    note: no code @ f1f0efee0e2d062f
7d0
  7d0
    note: return
201030
  201030
    note: invalid instruction @ 201030
580
  580
    note: indirect jump
5a0
  5a0
    note: indirect jump
590
  590
    note: indirect jump
7ffd40e44610
  7ffd40e44610
    note: no code @ 7ffd40e44610
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
#### LLVM
```llvm
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

; Function Attrs: noinline norecurse nounwind sspstrong
define { i64, i64 } @cn_div(i64 %rdi, i64 %rsi, i64 %rdx, i64 %rcx) local_unnamed_addr #15 {
"0x800":
  %0 = mul i64 %rdx, %rdx
  %1 = mul i64 %rcx, %rcx
  %2 = add i64 %1, %0
  %3 = mul i64 %rdx, %rdi
  %4 = mul i64 %rcx, %rsi
  %5 = mul i64 %rdx, %rsi
  %6 = add i64 %4, %3
  %7 = icmp slt i64 %rcx, 0
  %rcx.lobit = ashr i64 %rcx, 63
  %.rcx = xor i64 %rcx.lobit, %rcx
  %8 = icmp slt i64 %2, 0
  %9 = sub nsw i64 0, %2
  %..i.i = select i1 %8, i64 %9, i64 %2
  %10 = icmp eq i64 %.rcx, 0
  br i1 %10, label %.loopexit.i.i, label %.preheader.i.i.i.preheader

.preheader.i.i.i.preheader:                       ; preds = %"0x800"
  br label %.preheader.i.i.i

.preheader.i.i.i:                                 ; preds = %.preheader.i.i.i.preheader, %.preheader.i.i.i
  %.03036.i.i.i = phi i32 [ %19, %.preheader.i.i.i ], [ 0, %.preheader.i.i.i.preheader ]
  %.03135.i.i.i = phi i64 [ %18, %.preheader.i.i.i ], [ undef, %.preheader.i.i.i.preheader ]
  %.03234.i.i.i = phi i64 [ %.1.i.i.i, %.preheader.i.i.i ], [ %.rcx, %.preheader.i.i.i.preheader ]
  %11 = shl i64 %.03234.i.i.i, 1
  %12 = lshr i64 %.03135.i.i.i, 63
  %13 = or i64 %11, %12
  %14 = icmp sgt i64 %.03234.i.i.i, -1
  %15 = icmp ult i64 %13, %..i.i
  %or.cond.i.i.i = and i1 %14, %15
  %16 = select i1 %or.cond.i.i.i, i64 0, i64 %..i.i
  %.1.i.i.i = sub i64 %13, %16
  %not.or.cond.i.i.i.demorgan = and i1 %14, %15
  %not.or.cond.i.i.i = xor i1 %not.or.cond.i.i.i.demorgan, true
  %.029.i.i.i = zext i1 %not.or.cond.i.i.i to i64
  %17 = shl i64 %.03135.i.i.i, 1
  %18 = or i64 %.029.i.i.i, %17
  %19 = add nuw nsw i32 %.03036.i.i.i, 1
  %exitcond.i.i.i = icmp eq i32 %19, 64
  br i1 %exitcond.i.i.i, label %.loopexit.i.i.loopexit, label %.preheader.i.i.i, !llvm.loop !1098

.loopexit.i.i.loopexit:                           ; preds = %.preheader.i.i.i
  br label %.loopexit.i.i

.loopexit.i.i:                                    ; preds = %.loopexit.i.i.loopexit, %"0x800"
  %storemerge33.i.i.i = phi i64 [ 0, %"0x800" ], [ %18, %.loopexit.i.i.loopexit ]
  %storemerge.i.i.i = phi i64 [ 0, %"0x800" ], [ %.1.i.i.i, %.loopexit.i.i.loopexit ]
  %.lobit20.i.i = xor i64 %2, %rcx
  %20 = icmp slt i64 %.lobit20.i.i, 0
  br i1 %20, label %21, label %23

; <label>:21:                                     ; preds = %.loopexit.i.i
  %22 = sub i64 0, %storemerge33.i.i.i
  br i1 %7, label %._crit_edge.i.i, label %helper_idivq_EAX.exit

; <label>:23:                                     ; preds = %.loopexit.i.i
  %24 = icmp slt i64 %storemerge33.i.i.i, 0
  %.not.i.i = xor i1 %7, true
  %brmerge.i.i = or i1 %24, %.not.i.i
  br i1 %brmerge.i.i, label %helper_idivq_EAX.exit, label %._crit_edge.i.i

._crit_edge.i.i:                                  ; preds = %23, %21
  %.116.i = phi i64 [ %storemerge33.i.i.i, %23 ], [ %22, %21 ]
  %25 = sub i64 0, %storemerge.i.i.i
  br label %helper_idivq_EAX.exit

helper_idivq_EAX.exit:                            ; preds = %21, %23, %._crit_edge.i.i
  %.118.i = phi i64 [ %storemerge.i.i.i, %21 ], [ %25, %._crit_edge.i.i ], [ %storemerge.i.i.i, %23 ]
  %.217.i = phi i64 [ %22, %21 ], [ %.116.i, %._crit_edge.i.i ], [ %storemerge33.i.i.i, %23 ]
  %26 = mul i64 %.118.i, %rdi
  %27 = sub i64 %5, %26
  %28 = icmp slt i64 %.118.i, 0
  br i1 %28, label %29, label %neg128.exit.i.i2

; <label>:29:                                     ; preds = %helper_idivq_EAX.exit
  %30 = xor i64 %.118.i, -1
  %31 = sub i64 0, %.217.i
  %32 = icmp eq i64 %.217.i, 0
  %33 = sub i64 0, %.118.i
  %.24.i = select i1 %32, i64 %33, i64 %30
  br label %neg128.exit.i.i2

neg128.exit.i.i2:                                 ; preds = %29, %helper_idivq_EAX.exit
  %.015.i = phi i64 [ %.217.i, %helper_idivq_EAX.exit ], [ %31, %29 ]
  %34 = phi i64 [ %.118.i, %helper_idivq_EAX.exit ], [ %.24.i, %29 ]
  %35 = icmp eq i64 %34, 0
  br i1 %35, label %36, label %.preheader.i.i.i12.preheader

.preheader.i.i.i12.preheader:                     ; preds = %neg128.exit.i.i2
  br label %.preheader.i.i.i12

; <label>:36:                                     ; preds = %neg128.exit.i.i2
  %37 = udiv i64 %.015.i, %..i.i
  %38 = urem i64 %.015.i, %..i.i
  br label %.loopexit.i.i16

.preheader.i.i.i12:                               ; preds = %.preheader.i.i.i12.preheader, %.preheader.i.i.i12
  %.03036.i.i.i3 = phi i32 [ %47, %.preheader.i.i.i12 ], [ 0, %.preheader.i.i.i12.preheader ]
  %.03135.i.i.i4 = phi i64 [ %46, %.preheader.i.i.i12 ], [ %.015.i, %.preheader.i.i.i12.preheader ]
  %.03234.i.i.i5 = phi i64 [ %.1.i.i.i7, %.preheader.i.i.i12 ], [ %34, %.preheader.i.i.i12.preheader ]
  %39 = shl i64 %.03234.i.i.i5, 1
  %40 = lshr i64 %.03135.i.i.i4, 63
  %41 = or i64 %39, %40
  %42 = icmp sgt i64 %.03234.i.i.i5, -1
  %43 = icmp ult i64 %41, %..i.i
  %or.cond.i.i.i6 = and i1 %42, %43
  %44 = select i1 %or.cond.i.i.i6, i64 0, i64 %..i.i
  %.1.i.i.i7 = sub i64 %41, %44
  %not.or.cond.i.i.i9.demorgan = and i1 %42, %43
  %not.or.cond.i.i.i9 = xor i1 %not.or.cond.i.i.i9.demorgan, true
  %.029.i.i.i10 = zext i1 %not.or.cond.i.i.i9 to i64
  %45 = shl i64 %.03135.i.i.i4, 1
  %46 = or i64 %.029.i.i.i10, %45
  %47 = add nuw nsw i32 %.03036.i.i.i3, 1
  %exitcond.i.i.i11 = icmp eq i32 %47, 64
  br i1 %exitcond.i.i.i11, label %.loopexit.i.i16.loopexit, label %.preheader.i.i.i12, !llvm.loop !1098

.loopexit.i.i16.loopexit:                         ; preds = %.preheader.i.i.i12
  br label %.loopexit.i.i16

.loopexit.i.i16:                                  ; preds = %.loopexit.i.i16.loopexit, %36
  %storemerge33.i.i.i13 = phi i64 [ %37, %36 ], [ %46, %.loopexit.i.i16.loopexit ]
  %storemerge.i.i.i14 = phi i64 [ %38, %36 ], [ %.1.i.i.i7, %.loopexit.i.i16.loopexit ]
  %.lobit20.i.i15 = xor i64 %.118.i, %2
  %48 = icmp slt i64 %.lobit20.i.i15, 0
  br i1 %48, label %49, label %51

; <label>:49:                                     ; preds = %.loopexit.i.i16
  %50 = sub i64 0, %storemerge33.i.i.i13
  br i1 %28, label %._crit_edge.i.i20, label %helper_idivq_EAX.exit23

; <label>:51:                                     ; preds = %.loopexit.i.i16
  %52 = icmp slt i64 %storemerge33.i.i.i13, 0
  %.not.i.i17 = xor i1 %28, true
  %brmerge.i.i18 = or i1 %52, %.not.i.i17
  br i1 %brmerge.i.i18, label %helper_idivq_EAX.exit23, label %._crit_edge.i.i20

._crit_edge.i.i20:                                ; preds = %51, %49
  %.116.i19 = phi i64 [ %storemerge33.i.i.i13, %51 ], [ %50, %49 ]
  %53 = sub i64 0, %storemerge.i.i.i14
  br label %helper_idivq_EAX.exit23

helper_idivq_EAX.exit23:                          ; preds = %49, %51, %._crit_edge.i.i20
  %.118.i21 = phi i64 [ %storemerge.i.i.i14, %49 ], [ %53, %._crit_edge.i.i20 ], [ %storemerge.i.i.i14, %51 ]
  %.217.i22 = phi i64 [ %50, %49 ], [ %.116.i19, %._crit_edge.i.i20 ], [ %storemerge33.i.i.i13, %51 ]
  %rsp_1 = load i64, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 16, !alias.scope !1167
  %54 = add i64 %rsp_1, 8
  store i32 17, i32* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 6), align 8, !alias.scope !1167
  store i64 %27, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 3), align 16, !alias.scope !1167
  store i64 %26, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 4), align 8, !alias.scope !1167
  store i64 %.217.i22, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 5), align 16, !alias.scope !1167
  store i64 %.118.i21, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 1), align 8, !alias.scope !1167
  store i64 %54, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 4), align 16, !alias.scope !1167
  store i64 %27, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 6), align 16, !alias.scope !1167
  store i64 %26, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 7), align 8, !alias.scope !1167
  store i64 %6, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 8), align 16, !alias.scope !1167
  store i64 %2, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 9), align 8, !alias.scope !1167
  store i64 %rdx, i64* getelementptr inbounds (%struct.CPUX86State, %struct.CPUX86State* @cpu_state, i64 0, i32 0, i64 10), align 16, !alias.scope !1167
  %55 = insertvalue { i64, i64 } undef, i64 %6, 0
  %56 = insertvalue { i64, i64 } %55, i64 %27, 1
  ret { i64, i64 } %56
}
```
# How to Build
```bash
export JOVE_SRC_DIR=/path/to/jove
git clone git@github.mit.edu:an23640/jove.git $JOVE_SRC_DIR
```
## Preparation (Linux)
### Tools
```bash
# on ArchLinux
sudo pacman -S parallel
```
### Libraries
#### Boost
```bash
# on Archlinux
sudo pacman -S boost
```
#### LLVM
```bash
# on ArchLinux
sudo pacman -S llvm clang llvm-ocaml boost lld lldb
```
#### OCamlgraph
```bash
# on ArchLinux
yaourt -S ocaml-ocamlgraph
```
#### QEMU 2.6.2
```bash
export QEMU_SRC_DIR=/path/to/qemu
git clone https://github.com/qemu/qemu.git -b v2.6.2 $QEMU_SRC_DIR
cd $QEMU_SRC_DIR
patch -p1 < $JOVE_SRC_DIR/patches/qemu.patch
cd -
export QEMU_BUILD_DIR=/path/to/qemu/build/directory
mkdir -p $QEMU_BUILD_DIR
cd $QEMU_BUILD_DIR
CC=clang CXX=clang++ $QEMU_SRC_DIR/configure --python=$(which python2) --target-list=aarch64-linux-user '--extra-cflags=-flto -fno-inline -fuse-ld=gold' --disable-werror --disable-gtk --disable-libnfs --disable-bzip2 --disable-numa --disable-lzo --disable-vhdx --disable-libssh2 --disable-seccomp --disable-opengl --disable-smartcard --disable-spice --disable-curses --disable-glusterfs --disable-rbd --disable-snappy --disable-tpm --disable-libusb --disable-nettle --disable-gnutls --disable-curl --disable-vnc --disable-kvm --disable-brlapi --disable-bluez --enable-tcg-interpreter --disable-fdt --disable-xfsctl --disable-pie --disable-docs --disable-vde --disable-gcrypt --disable-virglrenderer --disable-libiscsi --disable-usb-redir --disable-virtfs --disable-coroutine-pool --disable-archipelago --disable-rdma --disable-linux-aio --disable-netmap --disable-cap-ng --disable-attr --disable-vhost-net --disable-xen --disable-xen-pci-passthrough --disable-libssh2 --disable-slirp --disable-uuid --without-pixman --disable-tools --disable-system --enable-debug
make -j$(nproc)
```
## Building jove with `make(1)`
```bash
cd $JOVE_SRC_DIR
# $QEMU_SRC_DIR and $QEMU_BUILD_DIR must be set

# delete any existing build files
make clean
# must configure after cleaning
make configure
# build it!
make -j$(nproc)
```
