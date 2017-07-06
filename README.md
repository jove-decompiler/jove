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
#### LLVM
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<title>/tmp/tmp.8wjEEjTwgO.ll.html</title>
<meta name="Generator" content="Vim/8.0">
<meta name="plugin-version" content="vim7.4_v2">
<meta name="syntax" content="llvm">
<meta name="settings" content="use_css,pre_wrap,no_foldcolumn,expand_tabs,prevent_copy=">
<meta name="colorscheme" content="solarized">
<style type="text/css">
<!--
pre { white-space: pre-wrap; font-family: monospace; color: #8080ff; background-color: #808080; }
body { font-family: monospace; color: #8080ff; background-color: #808080; }
* { font-size: 1em; }
.Type { color: #804000; }
.Comment { color: #00ff00; }
.Constant { color: #008080; }
.Identifier { color: #0000c0; }
.Statement { color: #008000; }
-->
</style>

<script type='text/javascript'>
<!--

-->
</script>
</head>
<body>
<pre id='vimCodeElement'>
<span class="Comment">; ModuleID = 'complex-num.jv/bitcode/decompilation'</span>
<span class="Statement">source_filename</span> = <span class="Constant">&quot;complex-num&quot;</span>
<span class="Statement">target</span> <span class="Statement">datalayout</span> = <span class="Constant">&quot;e-m:e-i64:64-f80:128-n8:16:32:64-S128&quot;</span>
<span class="Statement">target</span> <span class="Statement">triple</span> = <span class="Constant">&quot;x86_64-unknown-linux-gnu&quot;</span>

<span class="Identifier">%struct.CPUX86State</span> = <span class="Type">type</span> { [<span class="Constant">16</span> x <span class="Type">i64</span>], <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, [<span class="Constant">6</span> x <span class="Identifier">%struct.SegmentCache</span>], <span class="Identifier">%struct.SegmentCache</span>, <span class="Identifier">%struct.SegmentCache</span>, <span class="Identifier">%struct.SegmentCache</span>, <span class="Identifier">%struct.SegmentCache</span>, [<span class="Constant">5</span> x <span class="Type">i64</span>], <span class="Type">i32</span>, [<span class="Constant">4</span> x <span class="Identifier">%struct.Int128</span>], <span class="Identifier">%struct.Int128</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Identifier">%struct.anon.13</span>, <span class="Type">i32</span>, <span class="Type">i16</span>, <span class="Type">i16</span>, [<span class="Constant">8</span> x <span class="Type">i8</span>], [<span class="Constant">8</span> x <span class="Type">i8</span>], [<span class="Constant">8</span> x <span class="Identifier">%union.FPReg</span>], <span class="Type">i16</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Identifier">%struct.float_status</span>, <span class="Identifier">%struct.floatx80</span>, <span class="Identifier">%struct.float_status</span>, <span class="Identifier">%struct.float_status</span>, <span class="Type">i32</span>, [<span class="Constant">32</span> x <span class="Identifier">%union.ZMMReg</span>], <span class="Identifier">%union.ZMMReg</span>, <span class="Identifier">%union.MMXReg</span>, [<span class="Constant">8</span> x <span class="Type">i64</span>], <span class="Type">i32</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, [<span class="Constant">3</span> x <span class="Type">i64</span>], [<span class="Constant">18</span> x <span class="Type">i64</span>], [<span class="Constant">18</span> x <span class="Type">i64</span>], <span class="Type">i64</span>, <span class="Type">i32</span>, <span class="Identifier">%struct.anon.13</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, [<span class="Constant">5</span> x <span class="Type">i64</span>], <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, [<span class="Constant">16</span> x <span class="Type">i64</span>], [<span class="Constant">4</span> x <span class="Type">i64</span>], [<span class="Constant">4</span> x <span class="Type">i64</span>], <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i64</span>, [<span class="Constant">8</span> x <span class="Type">i64</span>], <span class="Identifier">%union.anon.15</span>, <span class="Type">i32</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i16</span>, <span class="Type">i16</span>, <span class="Type">i16</span>, <span class="Type">i16</span>, <span class="Type">i32</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, [<span class="Constant">12</span> x <span class="Type">i32</span>], [<span class="Constant">12</span> x <span class="Type">i32</span>], [<span class="Constant">11</span> x <span class="Type">i64</span>], <span class="Type">i64</span>, [<span class="Constant">8</span> x <span class="Identifier">%struct.Int128</span>], <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i32</span>, <span class="Type">i8</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i8</span>*, <span class="Type">i64</span>, <span class="Type">i64</span>, [<span class="Constant">40</span> x <span class="Type">i64</span>], <span class="Type">i64</span>, <span class="Type">i16</span>, <span class="Type">i16</span>, <span class="Type">i16</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i32</span>, <span class="Type">i32</span>, [<span class="Constant">8</span> x <span class="Type">i8</span>] }
<span class="Identifier">%struct.SegmentCache</span> = <span class="Type">type</span> { <span class="Type">i32</span>, <span class="Type">i64</span>, <span class="Type">i32</span>, <span class="Type">i32</span> }
<span class="Identifier">%struct.Int128</span> = <span class="Type">type</span> { <span class="Type">i64</span>, <span class="Type">i64</span> }
<span class="Identifier">%union.FPReg</span> = <span class="Type">type</span> { <span class="Identifier">%struct.floatx80</span> }
<span class="Identifier">%struct.floatx80</span> = <span class="Type">type</span> { <span class="Type">i64</span>, <span class="Type">i16</span> }
<span class="Identifier">%struct.float_status</span> = <span class="Type">type</span> { <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i8</span>, <span class="Type">i8</span> }
<span class="Identifier">%union.ZMMReg</span> = <span class="Type">type</span> { [<span class="Constant">8</span> x <span class="Type">i64</span>] }
<span class="Identifier">%union.MMXReg</span> = <span class="Type">type</span> { [<span class="Constant">1</span> x <span class="Type">i64</span>] }
<span class="Identifier">%struct.anon.13</span> = <span class="Type">type</span> {}
<span class="Identifier">%union.anon.15</span> = <span class="Type">type</span> { [<span class="Constant">4</span> x <span class="Identifier">%struct.CPUBreakpoint</span>*] }
<span class="Identifier">%struct.CPUBreakpoint</span> = <span class="Type">type</span> { <span class="Type">i64</span>, <span class="Type">i32</span>, <span class="Identifier">%struct.anon.18</span> }
<span class="Identifier">%struct.anon.18</span> = <span class="Type">type</span> { <span class="Identifier">%struct.CPUBreakpoint</span>*, <span class="Identifier">%struct.CPUBreakpoint</span>** }
<span class="Identifier">%struct.__jove_sections</span> = <span class="Type">type</span> &lt;{ <span class="Identifier">%struct.__jove__interp</span>, <span class="Identifier">%struct.__jove__note_ABI-tag</span>, <span class="Identifier">%struct.__jove__note_gnu_build-id</span>, <span class="Identifier">%struct.__jove__gnu_hash</span>, [<span class="Constant">4</span> x <span class="Type">i8</span>], <span class="Identifier">%struct.__jove__dynsym</span>, <span class="Identifier">%struct.__jove__dynstr</span>, <span class="Identifier">%struct.__jove__gnu_version</span>, <span class="Identifier">%struct.__jove__gnu_version_r</span>, <span class="Identifier">%struct.__jove__rela_dyn</span>, <span class="Identifier">%struct.__jove__rela_plt</span>, <span class="Identifier">%struct.__jove__init</span>, [<span class="Constant">1</span> x <span class="Type">i8</span>], <span class="Identifier">%struct.__jove__plt</span>, <span class="Identifier">%struct.__jove__plt_got</span>, [<span class="Constant">8</span> x <span class="Type">i8</span>], <span class="Identifier">%struct.__jove__text</span>, [<span class="Constant">2</span> x <span class="Type">i8</span>], <span class="Identifier">%struct.__jove__fini</span>, [<span class="Constant">3</span> x <span class="Type">i8</span>], <span class="Identifier">%struct.__jove__rodata</span>, <span class="Identifier">%struct.__jove__eh_frame_hdr</span>, <span class="Identifier">%struct.__jove__eh_frame</span>, [<span class="Constant">2097908</span> x <span class="Type">i8</span>], <span class="Identifier">%struct.__jove__init_array</span>, <span class="Identifier">%struct.__jove__fini_array</span>, <span class="Identifier">%struct.__jove__dynamic</span>, <span class="Identifier">%struct.__jove__got</span>, <span class="Identifier">%struct.__jove__got_plt</span>, <span class="Identifier">%struct.__jove__data</span>, <span class="Identifier">%struct.__jove__bss</span> }&gt;
<span class="Identifier">%struct.__jove__interp</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">28</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__note_ABI-tag</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">32</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__note_gnu_build-id</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">36</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__gnu_hash</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">28</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__dynsym</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">216</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__dynstr</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">142</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__gnu_version</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">18</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__gnu_version_r</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">32</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__rela_dyn</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">192</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__rela_plt</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">72</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__init</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">23</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__plt</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">64</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__plt_got</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">8</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__text</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">770</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__fini</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">9</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__rodata</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">60</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__eh_frame_hdr</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">92</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__eh_frame</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">396</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__init_array</span> = <span class="Type">type</span> &lt;{ <span class="Type">i64</span>* }&gt;
<span class="Identifier">%struct.__jove__fini_array</span> = <span class="Type">type</span> &lt;{ <span class="Type">i64</span>* }&gt;
<span class="Identifier">%struct.__jove__dynamic</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">480</span> x <span class="Type">i8</span>] }&gt;
<span class="Identifier">%struct.__jove__got</span> = <span class="Type">type</span> &lt;{ <span class="Type">void</span> ()*, <span class="Type">void</span> ()*, <span class="Type">void</span> ()*, <span class="Type">void</span> ()*, <span class="Type">void</span> ()* }&gt;
<span class="Identifier">%struct.__jove__got_plt</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">24</span> x <span class="Type">i8</span>], <span class="Type">void</span> ()*, <span class="Type">void</span> ()*, <span class="Type">void</span> ()* }&gt;
<span class="Identifier">%struct.__jove__data</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">8</span> x <span class="Type">i8</span>], <span class="Type">i64</span>* }&gt;
<span class="Identifier">%struct.__jove__bss</span> = <span class="Type">type</span> &lt;{ [<span class="Constant">8</span> x <span class="Type">i8</span>] }&gt;

<span class="Identifier">@cpu_state</span> = <span class="Statement">external</span> <span class="Statement">thread_local</span> <span class="Statement">local_unnamed_addr</span> <span class="Statement">global</span> <span class="Identifier">%struct.CPUX86State</span>
<span class="Identifier">@__jove_sections</span> = <span class="Statement">global</span> <span class="Identifier">%struct.__jove_sections</span> &lt;{ <span class="Identifier">%struct.__jove__interp</span> &lt;{ [<span class="Constant">28</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;/lib64/ld-linux-x86-64.so.2\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__note_ABI-tag</span> &lt;{ [<span class="Constant">32</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\04\00\00\00\10\00\00\00\01\00\00\00GNU\00\00\00\00\00\02\00\00\00\06\00\00\00 \00\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__note_gnu_build-id</span> &lt;{ [<span class="Constant">36</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\04\00\00\00\14\00\00\00\03\00\00\00GNU\00\E3\12\9D\08\D1\DBQw\19\C1&lt;'H\22\09Xw&lt;\0B\A1&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__gnu_hash</span> &lt;{ [<span class="Constant">28</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\01\00\00\00\01\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00&quot;</span> }&gt;, [<span class="Constant">4</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Identifier">%struct.__jove__dynsym</span> &lt;{ [<span class="Constant">216</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00=\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0B\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\10\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00+\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00Y\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\17\00\00\00\12\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00h\00\00\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\1C\00\00\00\22\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__dynstr</span> &lt;{ [<span class="Constant">142</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\00libc.so.6\00puts\00printf\00atol\00__cxa_finalize\00__libc_start_main\00_ITM_deregisterTMCloneTable\00__gmon_start__\00_ITM_registerTMCloneTable\00GLIBC_2.2.5\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__gnu_version</span> &lt;{ [<span class="Constant">18</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\00\00\00\00\02\00\02\00\02\00\00\00\02\00\00\00\02\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__gnu_version_r</span> &lt;{ [<span class="Constant">32</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\01\00\01\00\01\00\00\00\10\00\00\00\00\00\00\00u\1Ai\09\00\00\02\00\82\00\00\00\00\00\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__rela_dyn</span> &lt;{ [<span class="Constant">192</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\E8\0D \00\00\00\00\00\08\00\00\00\00\00\00\00\B0\07\00\00\00\00\00\00\F0\0D \00\00\00\00\00\08\00\00\00\00\00\00\00p\07\00\00\00\00\00\008\10 \00\00\00\00\00\08\00\00\00\00\00\00\008\10 \00\00\00\00\00\D8\0F \00\00\00\00\00\06\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\E0\0F \00\00\00\00\00\06\00\00\00\04\00\00\00\00\00\00\00\00\00\00\00\E8\0F \00\00\00\00\00\06\00\00\00\05\00\00\00\00\00\00\00\00\00\00\00\F0\0F \00\00\00\00\00\06\00\00\00\07\00\00\00\00\00\00\00\00\00\00\00\F8\0F \00\00\00\00\00\06\00\00\00\08\00\00\00\00\00\00\00\00\00\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__rela_plt</span> &lt;{ [<span class="Constant">72</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\18\10 \00\00\00\00\00\07\00\00\00\02\00\00\00\00\00\00\00\00\00\00\00 \10 \00\00\00\00\00\07\00\00\00\03\00\00\00\00\00\00\00\00\00\00\00(\10 \00\00\00\00\00\07\00\00\00\06\00\00\00\00\00\00\00\00\00\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__init</span> &lt;{ [<span class="Constant">23</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;H\83\EC\08H\8B\05\85\0A \00H\85\C0t\02\FF\D0H\83\C4\08\C3&quot;</span> }&gt;, [<span class="Constant">1</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Identifier">%struct.__jove__plt</span> &lt;{ [<span class="Constant">64</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\FF5\92\0A \00\FF%\94\0A \00\0F\1F@\00\FF%\92\0A \00h\00\00\00\00\E9\E0\FF\FF\FF\FF%\8A\0A \00h\01\00\00\00\E9\D0\FF\FF\FF\FF%\82\0A \00h\02\00\00\00\E9\C0\FF\FF\FF&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__plt_got</span> &lt;{ [<span class="Constant">8</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\FF%B\0A \00f\90&quot;</span> }&gt;, [<span class="Constant">8</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Identifier">%struct.__jove__text</span> &lt;{ [<span class="Constant">770</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;AUATUSH\83\EC\08\83\FF\06t\19H\8D=\02\03\00\00\E8\A5\FF\FF\FF1\C0H\83\C4\08[]A\5CA]\C3H\8B~\08H\89\F31\C0\E8\AA\FF\FF\FFH\8B{\10Lc\E01\C0\E8\9C\FF\FF\FFH\8B{ Hc\E81\C0\E8\8E\FF\FF\FFH\8B{(Lc\E81\C0\E8\80\FF\FF\FFHc\C8H\8BC\18\0F\B6\00&lt;+tD~+&lt;-t[&lt;/uMH\89\EEL\89\EAL\89\E7\E8\BA\01\00\00H\89\C6H\8D=\B0\02\00\001\C0\E89\FF\FF\FF1\C0\EB\82&lt;*u&amp;H\89\EEL\89\EAL\89\E7\E8s\01\00\00H\89\C6\EB\D7H\89\EEL\89\EAL\89\E7\E8@\01\00\00H\89\C6\EB\C4\B8\01\00\00\00\E9N\FF\FF\FFH\89\EEL\89\EAL\89\E7\E83\01\00\00H\89\C6\EB\A7f.\0F\1F\84\00\00\00\00\00\0F\1F@\001\EDI\89\D1^H\89\E2H\83\E4\F0PTL\8D\05\FA\01\00\00H\8D\0D\83\01\00\00H\8D=\EC\FE\FF\FF\FF\15\06\09 \00\F4\0F\1FD\00\00H\8D=Y\09 \00UH\8D\05Q\09 \00H9\F8H\89\E5t\19H\8B\05\DA\08 \00H\85\C0t\0D]\FF\E0f.\0F\1F\84\00\00\00\00\00]\C3\0F\1F@\00f.\0F\1F\84\00\00\00\00\00H\8D=\19\09 \00H\8D5\12\09 \00UH)\FEH\89\E5H\C1\FE\03H\89\F0H\C1\E8?H\01\C6H\D1\FEt\18H\8B\05\A1\08 \00H\85\C0t\0C]\FF\E0f\0F\1F\84\00\00\00\00\00]\C3\0F\1F@\00f.\0F\1F\84\00\00\00\00\00\80=\C9\08 \00\00u/H\83=w\08 \00\00UH\89\E5t\0CH\8B=\AA\08 \00\E8\1D\FE\FF\FF\E8H\FF\FF\FF\C6\05\A1\08 \00\01]\C3\0F\1F\80\00\00\00\00\F3\C3f\0F\1FD\00\00UH\89\E5]\E9f\FF\FF\FFf\0F\1FD\00\00H\01\CEH\8D\04\17H\89\F2\C3\0F\1FD\00\00H)\CEH\89\F8H)\D0H\89\F2\C3\0F\1F\00H\89\F8I\89\F0H\0F\AF\C2L\0F\AF\C1H\0F\AF\F2L)\C0H\0F\AF\F9H\8D\14&gt;\C3f\90I\89\D1H\89\C8I\89\D2L\0F\AF\CAH\0F\AF\C1I\01\C1H\89\F8H\0F\AF\C2H\89\F2H\0F\AF\D1I\0F\AF\F2H\01\D0H\99I\F7\F9H\0F\AF\F9I\89\C0H)\FEH\89\F0H\99I\F7\F9H\89\C6L\89\C0H\89\F2\C3f\0F\1FD\00\00AWAVI\89\D7AUATL\8D%\86\05 \00UH\8D-\86\05 \00SA\89\FDI\89\F6L)\E5H\83\EC\08H\C1\FD\03\E8\D7\FC\FF\FFH\85\EDt 1\DB\0F\1F\84\00\00\00\00\00L\89\FAL\89\F6D\89\EFA\FF\14\DCH\83\C3\01H9\DDu\EAH\83\C4\08[]A\5CA]A^A_\C3\90f.\0F\1F\84\00\00\00\00\00\F3\C3&quot;</span> }&gt;, [<span class="Constant">2</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Identifier">%struct.__jove__fini</span> &lt;{ [<span class="Constant">9</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;H\83\EC\08H\83\C4\08\C3&quot;</span> }&gt;, [<span class="Constant">3</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Identifier">%struct.__jove__rodata</span> &lt;{ [<span class="Constant">60</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\01\00\02\00\00\00\00\00usage: complex-num w x [+-*/] y z\00\00\00\00\00\00\00%li + %lii\0A\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__eh_frame_hdr</span> &lt;{ [<span class="Constant">92</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\01\1B\03;X\00\00\00\0A\00\00\00d\FC\FF\FF\A4\00\00\00\A4\FC\FF\FF\CC\00\00\00\B4\FC\FF\FFD\01\00\00\A4\FD\FF\FFt\00\00\00\B4\FE\FF\FF\E4\00\00\00\C4\FE\FF\FF\FC\00\00\00\D4\FE\FF\FF\14\01\00\00\F4\FE\FF\FF,\01\00\00D\FF\FF\FF\84\01\00\00\B4\FF\FF\FF\CC\01\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__eh_frame</span> &lt;{ [<span class="Constant">396</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\14\00\00\00\00\00\00\00\01zR\00\01x\10\01\1B\0C\07\08\90\01\07\10\14\00\00\00\1C\00\00\00(\FD\FF\FF+\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\00\00\00\00\01zR\00\01x\10\01\1B\0C\07\08\90\01\00\00$\00\00\00\1C\00\00\00\B8\FB\FF\FF@\00\00\00\00\0E\10F\0E\18J\0F\0Bw\08\80\00?\1A;*3$\22\00\00\00\00\14\00\00\00D\00\00\00\D0\FB\FF\FF\08\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\5C\00\00\00\C8\FD\FF\FF\0B\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00t\00\00\00\C0\FD\FF\FF\0D\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\8C\00\00\00\B8\FD\FF\FF\1E\00\00\00\00\00\00\00\00\00\00\00\14\00\00\00\A4\00\00\00\C0\FD\FF\FFJ\00\00\00\00\00\00\00\00\00\00\00&lt;\00\00\00\BC\00\00\00h\FB\FF\FF\E2\00\00\00\00B\0E\10\8D\02B\0E\18\8C\03A\0E \86\04A\0E(\83\05D\0E0W\0A\0E(A\0E A\0E\18B\0E\10B\0E\08A\0B\00\00\00\00\00\00D\00\00\00\FC\00\00\00\B8\FD\FF\FFe\00\00\00\00B\0E\10\8F\02B\0E\18\8E\03E\0E \8D\04B\0E(\8C\05H\0E0\86\06H\0E8\83\07M\0E@r\0E8A\0E0A\0E(B\0E B\0E\18B\0E\10B\0E\08\00\14\00\00\00D\01\00\00\E0\FD\FF\FF\02\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00&quot;</span> }&gt;, [<span class="Constant">2097908</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Identifier">%struct.__jove__init_array</span> &lt;{ <span class="Type">i64</span>* <span class="Statement">bitcast</span> (<span class="Type">i8</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">16</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">496</span>) <span class="Statement">to</span> <span class="Type">i64</span>*) }&gt;, <span class="Identifier">%struct.__jove__fini_array</span> &lt;{ <span class="Type">i64</span>* <span class="Statement">bitcast</span> (<span class="Type">i8</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">16</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">432</span>) <span class="Statement">to</span> <span class="Type">i64</span>*) }&gt;, <span class="Identifier">%struct.__jove__dynamic</span> &lt;{ [<span class="Constant">480</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\01\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\0C\00\00\00\00\00\00\00X\05\00\00\00\00\00\00\0D\00\00\00\00\00\00\00\C4\08\00\00\00\00\00\00\19\00\00\00\00\00\00\00\E8\0D \00\00\00\00\00\1B\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\1A\00\00\00\00\00\00\00\F0\0D \00\00\00\00\00\1C\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\F5\FE\FFo\00\00\00\00\98\02\00\00\00\00\00\00\05\00\00\00\00\00\00\00\90\03\00\00\00\00\00\00\06\00\00\00\00\00\00\00\B8\02\00\00\00\00\00\00\0A\00\00\00\00\00\00\00\8E\00\00\00\00\00\00\00\0B\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\15\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\00\10 \00\00\00\00\00\02\00\00\00\00\00\00\00H\00\00\00\00\00\00\00\14\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00\17\00\00\00\00\00\00\00\10\05\00\00\00\00\00\00\07\00\00\00\00\00\00\00P\04\00\00\00\00\00\00\08\00\00\00\00\00\00\00\C0\00\00\00\00\00\00\00\09\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\FB\FF\FFo\00\00\00\00\00\00\00\08\00\00\00\00\FE\FF\FFo\00\00\00\000\04\00\00\00\00\00\00\FF\FF\FFo\00\00\00\00\01\00\00\00\00\00\00\00\F0\FF\FFo\00\00\00\00\1E\04\00\00\00\00\00\00\F9\FF\FFo\00\00\00\00\03\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00&quot;</span> }&gt;, <span class="Identifier">%struct.__jove__got</span> &lt;{ <span class="Type">void</span> ()* <span class="Identifier">@_ITM_deregisterTMCloneTable</span>, <span class="Type">void</span> ()* <span class="Identifier">@__libc_start_main</span>, <span class="Type">void</span> ()* <span class="Identifier">@__gmon_start__</span>, <span class="Type">void</span> ()* <span class="Identifier">@_ITM_registerTMCloneTable</span>, <span class="Type">void</span> ()* <span class="Identifier">@__cxa_finalize</span> }&gt;, <span class="Identifier">%struct.__jove__got_plt</span> &lt;{ [<span class="Constant">24</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;\F8\0D \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00&quot;</span>, <span class="Type">void</span> ()* <span class="Identifier">@puts</span>, <span class="Type">void</span> ()* <span class="Identifier">@printf</span>, <span class="Type">void</span> ()* <span class="Identifier">@atol</span> }&gt;, <span class="Identifier">%struct.__jove__data</span> &lt;{ [<span class="Constant">8</span> x <span class="Type">i8</span>] <span class="Constant">zeroinitializer</span>, <span class="Type">i64</span>* <span class="Statement">bitcast</span> (<span class="Type">i64</span>** <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">29</span>, <span class="Type">i32</span> <span class="Constant">1</span>) <span class="Statement">to</span> <span class="Type">i64</span>*) }&gt;, <span class="Identifier">%struct.__jove__bss</span> &lt;{ [<span class="Constant">8</span> x <span class="Type">i8</span>] <span class="Statement">c</span><span class="Constant">&quot;GCC: (GN&quot;</span> }&gt; }&gt;, <span class="Statement">align</span> <span class="Constant">4096</span>

<span class="Statement">declare</span> <span class="Statement">extern_weak</span> <span class="Type">void</span> <span class="Identifier">@_ITM_deregisterTMCloneTable</span>()

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@__libc_start_main</span>()

<span class="Statement">declare</span> <span class="Statement">extern_weak</span> <span class="Type">void</span> <span class="Identifier">@__gmon_start__</span>()

<span class="Statement">declare</span> <span class="Statement">extern_weak</span> <span class="Type">void</span> <span class="Identifier">@_ITM_registerTMCloneTable</span>()

<span class="Statement">declare</span> <span class="Statement">extern_weak</span> <span class="Type">void</span> <span class="Identifier">@__cxa_finalize</span>()

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@puts</span>()

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@printf</span>()

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@atol</span>()

<span class="Comment">; Function Attrs: noinline noreturn</span>
<span class="Statement">define</span> <span class="Type">void</span> <span class="Identifier">@_start</span>(<span class="Type">i64</span> <span class="Identifier">%rdx</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">0</span> {
<span class="Constant">&quot;0x6b0&quot;</span>:
  <span class="Identifier">%rax_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rsp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">8</span>
  <span class="Identifier">%1</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Constant">-16</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Constant">-8</span>
  <span class="Identifier">%3</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%2</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rax_1</span>, <span class="Type">i64</span>* <span class="Identifier">%3</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%4</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Constant">-16</span>
  <span class="Identifier">%5</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%4</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Identifier">%5</span>, <span class="Statement">align</span> <span class="Constant">16</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%6</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Constant">-24</span>
  <span class="Identifier">%7</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%6</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1754</span>, <span class="Type">i64</span>* <span class="Identifier">%7</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_indirect_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@__libc_start_main</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x6da&quot;</span>

<span class="Constant">&quot;0x6da&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x6da&quot;, %&quot;0x6b0&quot;</span>
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x6da&quot;</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_add</span>(<span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span> <span class="Identifier">%rcx</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x7c0&quot;</span>:
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Identifier">%rsi</span>
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%1</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Identifier">%rdi</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">9</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%3</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Constant">undef</span>, <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Constant">0</span>
  <span class="Identifier">%4</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%3</span>, <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Constant">1</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%4</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> <span class="Statement">internal</span> <span class="Type">void</span> @<span class="Constant">&quot;0x5a0&quot;</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x5a0&quot;</span>:
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@atol</span>)
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> { <span class="Type">i64</span> } <span class="Identifier">@_init</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x558&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-8</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Statement">icmp</span> <span class="Statement">eq</span> (<span class="Type">void</span> ()* <span class="Identifier">@__gmon_start__</span>, <span class="Type">void</span> ()* <span class="Constant">null</span>), <span class="Type">label</span> %<span class="Constant">&quot;0x56a.exit&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x568&quot;</span>

<span class="Constant">&quot;0x568&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x558&quot;</span>
  <span class="Identifier">%1</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-16</span>
  <span class="Identifier">%2</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%1</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1386</span>, <span class="Type">i64</span>* <span class="Identifier">%2</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_indirect_call</span>(<span class="Type">void</span> ()* <span class="Identifier">@__gmon_start__</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x56a.exit&quot;</span>

<span class="Constant">&quot;0x56a.exit&quot;</span>:                                     <span class="Comment">; preds = %&quot;0x568&quot;, %&quot;0x558&quot;</span>
  <span class="Identifier">%rsp_.0</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Identifier">%1</span>, %<span class="Constant">&quot;0x568&quot;</span> ], [ <span class="Identifier">%0</span>, %<span class="Constant">&quot;0x558&quot;</span> ]
  <span class="Identifier">%3</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.0</span>, <span class="Constant">8</span>
  <span class="Identifier">%4</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.0</span>, <span class="Constant">16</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">9</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%3</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">8</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%4</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span> } { <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">void</span> ()* <span class="Identifier">@__gmon_start__</span> <span class="Statement">to</span> <span class="Type">i64</span>) }
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> <span class="Statement">internal</span> <span class="Type">void</span> @<span class="Constant">&quot;0x5b0&quot;</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x5b0&quot;</span>:
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* <span class="Identifier">@__cxa_finalize</span>)
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_div</span>(<span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span> <span class="Identifier">%rcx</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x800&quot;</span>:
  <span class="Identifier">%0</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Identifier">%rdx</span>
  <span class="Identifier">%1</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Identifier">%rcx</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Identifier">%0</span>
  <span class="Identifier">%3</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Identifier">%rdi</span>
  <span class="Identifier">%4</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Identifier">%rsi</span>
  <span class="Identifier">%5</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Identifier">%rsi</span>
  <span class="Identifier">%6</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%4</span>, <span class="Identifier">%3</span>
  <span class="Identifier">%7</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@helper_idivq_EAX</span>(<span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span> <span class="Constant">undef</span>, <span class="Type">i64</span> <span class="Identifier">%rcx</span>)
  <span class="Identifier">%8</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%7</span>, <span class="Constant">0</span>
  <span class="Identifier">%9</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%7</span>, <span class="Constant">1</span>
  <span class="Identifier">%10</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%9</span>, <span class="Identifier">%rdi</span>
  <span class="Identifier">%11</span> = <span class="Statement">sub</span> <span class="Type">i64</span> <span class="Identifier">%5</span>, <span class="Identifier">%10</span>
  <span class="Identifier">%12</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@helper_idivq_EAX</span>(<span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span> <span class="Identifier">%8</span>, <span class="Type">i64</span> <span class="Identifier">%9</span>)
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%13</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Identifier">%14</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%12</span>, <span class="Constant">1</span>
  <span class="Identifier">%15</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%12</span>, <span class="Constant">0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">17</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%11</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%10</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%15</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%14</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">1</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%13</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%11</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%10</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%6</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">8</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">9</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">10</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%16</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Constant">undef</span>, <span class="Type">i64</span> <span class="Identifier">%6</span>, <span class="Constant">0</span>
  <span class="Identifier">%17</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%16</span>, <span class="Type">i64</span> <span class="Identifier">%11</span>, <span class="Constant">1</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%17</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> <span class="Type">void</span> <span class="Identifier">@__libc_csu_init</span>(<span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span> <span class="Identifier">%rdx</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x850&quot;</span>:
  <span class="Identifier">%rbx_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rsp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_3</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r12_4</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r13_5</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r14_6</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">14</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r15_7</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">15</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-8</span>
  <span class="Identifier">%1</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%0</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%r15_7</span>, <span class="Type">i64</span>* <span class="Identifier">%1</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-16</span>
  <span class="Identifier">%3</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%2</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%r14_6</span>, <span class="Type">i64</span>* <span class="Identifier">%3</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%4</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-24</span>
  <span class="Identifier">%5</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%4</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%r13_5</span>, <span class="Type">i64</span>* <span class="Identifier">%5</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%6</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-32</span>
  <span class="Identifier">%7</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%6</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%r12_4</span>, <span class="Type">i64</span>* <span class="Identifier">%7</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%8</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-40</span>
  <span class="Identifier">%9</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%8</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbp_3</span>, <span class="Type">i64</span>* <span class="Identifier">%9</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%10</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-48</span>
  <span class="Identifier">%11</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%10</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbx_1</span>, <span class="Type">i64</span>* <span class="Identifier">%11</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%12</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-64</span>
  <span class="Identifier">%13</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%12</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">2177</span>, <span class="Type">i64</span>* <span class="Identifier">%13</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%14</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Constant">4294967295</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">41</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%12</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Identifier">%struct.__jove__init_array</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">24</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%14</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">14</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">15</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%15</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span> } <span class="Identifier">@_init</span>()
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">void</span> ()* <span class="Identifier">@__gmon_start__</span> <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rsp_8</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_9</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r12_10</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%not.</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%rbp_9</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%not.</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x8a6&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x886&quot;</span>

<span class="Constant">&quot;0x886&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x850&quot;</span>
  <span class="Identifier">%16</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%r12_10</span> <span class="Statement">to</span> <span class="Type">void</span> ()**
  <span class="Identifier">%17</span> = <span class="Statement">load</span> <span class="Type">void</span> ()*, <span class="Type">void</span> ()** <span class="Identifier">%16</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%18</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_8</span>, <span class="Constant">-8</span>
  <span class="Identifier">%19</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%18</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">2205</span>, <span class="Type">i64</span>* <span class="Identifier">%19</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_indirect_call</span>(<span class="Type">void</span> ()* <span class="Identifier">%17</span>)
  <span class="Identifier">%20</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%rbp_9</span>, <span class="Constant">1</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%20</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x8a6&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x890.preheader&quot;</span>

<span class="Constant">&quot;0x890.preheader&quot;</span>:                                <span class="Comment">; preds = %&quot;0x886&quot;</span>
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x890&quot;</span>

<span class="Constant">&quot;0x8a6.loopexit&quot;</span>:                                 <span class="Comment">; preds = %&quot;0x890&quot;</span>
  <span class="Identifier">%21</span> = <span class="Statement">shl</span> <span class="Type">i64</span> <span class="Identifier">%rbp_9</span>, <span class="Constant">3</span>
  <span class="Identifier">%22</span> = <span class="Statement">sub</span> <span class="Type">i64</span> <span class="Identifier">%rsp_8</span>, <span class="Identifier">%21</span>
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x8a6&quot;</span>

<span class="Constant">&quot;0x8a6&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x8a6.loopexit&quot;, %&quot;0x886&quot;, %&quot;0x850&quot;</span>
  <span class="Identifier">%rsp_.1</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Identifier">%rsp_8</span>, %<span class="Constant">&quot;0x850&quot;</span> ], [ <span class="Identifier">%18</span>, %<span class="Constant">&quot;0x886&quot;</span> ], [ <span class="Identifier">%22</span>, %<span class="Constant">&quot;0x8a6.loopexit&quot;</span> ]
  <span class="Identifier">%23</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">8</span>
  <span class="Identifier">%24</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">48</span>
  <span class="Identifier">%25</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">40</span>
  <span class="Identifier">%26</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">32</span>
  <span class="Identifier">%27</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">24</span>
  <span class="Identifier">%28</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">16</span>
  <span class="Identifier">%29</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">64</span>
  <span class="Identifier">%30</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%24</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%31</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%30</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%32</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%25</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%33</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%32</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%34</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%26</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%35</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%34</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%36</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%27</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%37</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%36</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%38</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%28</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%39</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%38</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%40</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%23</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%41</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%40</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">9</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%23</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">8</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%41</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%29</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%39</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%37</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%35</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%33</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">14</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%31</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">15</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> <span class="Type">void</span>

<span class="Constant">&quot;0x890&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x890&quot;, %&quot;0x890.preheader&quot;</span>
  <span class="Identifier">%42</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Identifier">%49</span>, %<span class="Constant">&quot;0x890&quot;</span> ], [ <span class="Constant">1</span>, %<span class="Constant">&quot;0x890.preheader&quot;</span> ]
  <span class="Identifier">%rsp_.043</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Identifier">%47</span>, %<span class="Constant">&quot;0x890&quot;</span> ], [ <span class="Identifier">%18</span>, %<span class="Constant">&quot;0x890.preheader&quot;</span> ]
  <span class="Identifier">%43</span> = <span class="Statement">shl</span> <span class="Type">i64</span> <span class="Identifier">%42</span>, <span class="Constant">3</span>
  <span class="Identifier">%44</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%43</span>, <span class="Identifier">%r12_10</span>
  <span class="Identifier">%45</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%44</span> <span class="Statement">to</span> <span class="Type">void</span> ()**
  <span class="Identifier">%46</span> = <span class="Statement">load</span> <span class="Type">void</span> ()*, <span class="Type">void</span> ()** <span class="Identifier">%45</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%47</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.043</span>, <span class="Constant">-8</span>
  <span class="Identifier">%48</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%47</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">2205</span>, <span class="Type">i64</span>* <span class="Identifier">%48</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_indirect_call</span>(<span class="Type">void</span> ()* <span class="Identifier">%46</span>)
  <span class="Identifier">%49</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%42</span>, <span class="Constant">1</span>
  <span class="Identifier">%50</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%rbp_9</span>, <span class="Identifier">%49</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%50</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x8a6.loopexit&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x890&quot;</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> <span class="Statement">internal</span> <span class="Type">void</span> @<span class="Constant">&quot;0x590&quot;</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x590&quot;</span>:
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@printf</span>)
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_mul</span>(<span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span> <span class="Identifier">%rcx</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x7e0&quot;</span>:
  <span class="Identifier">%0</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Identifier">%rsi</span>
  <span class="Identifier">%1</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Identifier">%rsi</span>
  <span class="Identifier">%2</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Identifier">%rdi</span>
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%3</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Identifier">%4</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Identifier">%1</span>
  <span class="Identifier">%5</span> = <span class="Statement">ashr</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Constant">63</span>
  <span class="Identifier">%6</span> = <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">i64</span> <span class="Identifier">@helper_mulsh_i64</span>(<span class="Type">i64</span> <span class="Identifier">%rcx</span>, <span class="Type">i64</span> <span class="Identifier">%rdi</span>)
  <span class="Identifier">%7</span> = <span class="Statement">sub</span> <span class="Type">i64</span> <span class="Identifier">%5</span>, <span class="Identifier">%6</span>
  <span class="Identifier">%8</span> = <span class="Statement">mul</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Identifier">%rdi</span>
  <span class="Identifier">%9</span> = <span class="Statement">sub</span> <span class="Type">i64</span> <span class="Identifier">%8</span>, <span class="Identifier">%0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">5</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%7</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%3</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">8</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%10</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Constant">undef</span>, <span class="Type">i64</span> <span class="Identifier">%9</span>, <span class="Constant">0</span>
  <span class="Identifier">%11</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%10</span>, <span class="Type">i64</span> <span class="Identifier">%4</span>, <span class="Constant">1</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%11</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> { <span class="Type">i64</span> } <span class="Identifier">@main</span>(<span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Type">i64</span> <span class="Identifier">%rsi</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x5c0&quot;</span>:
  <span class="Identifier">%rbx_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rsp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_3</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r12_4</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r13_5</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-8</span>
  <span class="Identifier">%1</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%0</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%r13_5</span>, <span class="Type">i64</span>* <span class="Identifier">%1</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-16</span>
  <span class="Identifier">%3</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%2</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%r12_4</span>, <span class="Type">i64</span>* <span class="Identifier">%3</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%4</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-24</span>
  <span class="Identifier">%5</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%4</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbp_3</span>, <span class="Type">i64</span>* <span class="Identifier">%5</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%6</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-32</span>
  <span class="Identifier">%7</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%6</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbx_1</span>, <span class="Type">i64</span>* <span class="Identifier">%7</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%8</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Constant">-6</span>
  <span class="Identifier">%9</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%8</span>, <span class="Constant">4294967295</span>
  <span class="Identifier">%not.</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%9</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%not.</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x5e8&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x5cf&quot;</span>

<span class="Constant">&quot;0x5cf&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x5c0&quot;</span>
  <span class="Identifier">%10</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-48</span>
  <span class="Identifier">%11</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%10</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1499</span>, <span class="Type">i64</span>* <span class="Identifier">%11</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">16</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%8</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">6</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%10</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">i8</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">20</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">8</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@puts</span>)
  <span class="Identifier">%rsp_11</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%12</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_11</span>, <span class="Constant">8</span>
  <span class="Identifier">%13</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_11</span>, <span class="Constant">32</span>
  <span class="Identifier">%14</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_11</span>, <span class="Constant">24</span>
  <span class="Identifier">%15</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_11</span>, <span class="Constant">16</span>
  <span class="Identifier">%16</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_11</span>, <span class="Constant">48</span>
  <span class="Identifier">%17</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%13</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%18</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%17</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%19</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%14</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%20</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%19</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%21</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%15</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%22</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%21</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%23</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%12</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%24</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%23</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">9</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%12</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">8</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%24</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%16</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%22</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%20</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%18</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span> } <span class="Constant">zeroinitializer</span>

<span class="Constant">&quot;0x5e8&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x5c0&quot;</span>
  <span class="Identifier">%25</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Constant">8</span>
  <span class="Identifier">%26</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%25</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%27</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%26</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%28</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_2</span>, <span class="Constant">-48</span>
  <span class="Identifier">%29</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%28</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1526</span>, <span class="Type">i64</span>* <span class="Identifier">%29</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">49</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%28</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%27</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@atol</span>)
  <span class="Identifier">%rsp_25</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbx_24</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rax_23</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%30</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rbx_24</span>, <span class="Constant">16</span>
  <span class="Identifier">%31</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%30</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%32</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%31</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%33</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_25</span>, <span class="Constant">-8</span>
  <span class="Identifier">%34</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%33</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1540</span>, <span class="Type">i64</span>* <span class="Identifier">%34</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%sext</span> = <span class="Statement">shl</span> <span class="Type">i64</span> <span class="Identifier">%rax_23</span>, <span class="Constant">32</span>
  <span class="Identifier">%35</span> = <span class="Statement">ashr</span> <span class="Statement">exact</span> <span class="Type">i64</span> <span class="Identifier">%sext</span>, <span class="Constant">32</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">49</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%33</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%32</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%35</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@atol</span>)
  <span class="Identifier">%rsp_33</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbx_32</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rax_31</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%36</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rbx_32</span>, <span class="Constant">32</span>
  <span class="Identifier">%37</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%36</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%38</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%37</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%39</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_33</span>, <span class="Constant">-8</span>
  <span class="Identifier">%40</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%39</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1554</span>, <span class="Type">i64</span>* <span class="Identifier">%40</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%sext165</span> = <span class="Statement">shl</span> <span class="Type">i64</span> <span class="Identifier">%rax_31</span>, <span class="Constant">32</span>
  <span class="Identifier">%41</span> = <span class="Statement">ashr</span> <span class="Statement">exact</span> <span class="Type">i64</span> <span class="Identifier">%sext165</span>, <span class="Constant">32</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">49</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%39</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%41</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%38</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@atol</span>)
  <span class="Identifier">%rsp_42</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbx_41</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rax_40</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%42</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rbx_41</span>, <span class="Constant">40</span>
  <span class="Identifier">%43</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%42</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%44</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%43</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%45</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_42</span>, <span class="Constant">-8</span>
  <span class="Identifier">%46</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%45</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1568</span>, <span class="Type">i64</span>* <span class="Identifier">%46</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%sext166</span> = <span class="Statement">shl</span> <span class="Type">i64</span> <span class="Identifier">%rax_40</span>, <span class="Constant">32</span>
  <span class="Identifier">%47</span> = <span class="Statement">ashr</span> <span class="Statement">exact</span> <span class="Type">i64</span> <span class="Identifier">%sext166</span>, <span class="Constant">32</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">49</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%45</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%44</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%47</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@atol</span>)
  <span class="Identifier">%rsp_52</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_53</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r12_54</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%r13_55</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbx_51</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rax_50</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%sext167</span> = <span class="Statement">shl</span> <span class="Type">i64</span> <span class="Identifier">%rax_50</span>, <span class="Constant">32</span>
  <span class="Identifier">%48</span> = <span class="Statement">ashr</span> <span class="Statement">exact</span> <span class="Type">i64</span> <span class="Identifier">%sext167</span>, <span class="Constant">32</span>
  <span class="Identifier">%49</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rbx_51</span>, <span class="Constant">24</span>
  <span class="Identifier">%50</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%49</span> <span class="Statement">to</span> <span class="Type">i64</span>**
  <span class="Identifier">%51</span> = <span class="Statement">load</span> <span class="Type">i64</span>*, <span class="Type">i64</span>** <span class="Identifier">%50</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%52</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%51</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%53</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%52</span>, <span class="Constant">4294967295</span>
  <span class="Identifier">%54</span> = <span class="Statement">add</span> <span class="Statement">nsw</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Constant">-43</span>
  <span class="Identifier">%fold</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%52</span>, <span class="Constant">213</span>
  <span class="Identifier">%55</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%fold</span>, <span class="Constant">255</span>
  <span class="Identifier">%not.180</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%55</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%not.180</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x672&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x62e&quot;</span>

<span class="Constant">&quot;0x62e&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x5e8&quot;</span>
  <span class="Identifier">%56</span> = <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">i64</span> <span class="Identifier">@helper_cc_compute_all</span>(<span class="Type">i64</span> <span class="Identifier">%54</span>, <span class="Type">i64</span> <span class="Constant">43</span>, <span class="Type">i64</span> <span class="Constant">undef</span>, <span class="Type">i32</span> <span class="Constant">14</span>)
  <span class="Identifier">%57</span> = <span class="Statement">lshr</span> <span class="Type">i64</span> <span class="Identifier">%56</span>, <span class="Constant">4</span>
  <span class="Identifier">%58</span> = <span class="Statement">xor</span> <span class="Type">i64</span> <span class="Identifier">%57</span>, <span class="Identifier">%56</span>
  <span class="Identifier">%59</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%58</span>, <span class="Constant">192</span>
  <span class="Identifier">%60</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%59</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%60</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x630&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x65b&quot;</span>

<span class="Constant">&quot;0x630&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x62e&quot;</span>
  <span class="Identifier">%fold169</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%52</span>, <span class="Constant">211</span>
  <span class="Identifier">%61</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%fold169</span>, <span class="Constant">255</span>
  <span class="Identifier">%not.181</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%61</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%not.181</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x68f&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x634&quot;</span>

<span class="Constant">&quot;0x634&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x630&quot;</span>
  <span class="Identifier">%fold170</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%52</span>, <span class="Constant">209</span>
  <span class="Identifier">%62</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%fold170</span>, <span class="Constant">255</span>
  <span class="Identifier">%63</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%62</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%63</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x638&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x5dd&quot;</span>

<span class="Constant">&quot;0x638&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x634&quot;</span>
  <span class="Identifier">%64</span> = <span class="Statement">add</span> <span class="Statement">nsw</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Constant">-47</span>
  <span class="Identifier">%65</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_52</span>, <span class="Constant">-8</span>
  <span class="Identifier">%66</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%65</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1606</span>, <span class="Type">i64</span>* <span class="Identifier">%66</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">14</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">47</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%65</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%67</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_div</span>(<span class="Type">i64</span> <span class="Identifier">%r12_54</span>, <span class="Type">i64</span> <span class="Identifier">%rbp_53</span>, <span class="Type">i64</span> <span class="Identifier">%r13_55</span>, <span class="Type">i64</span> <span class="Identifier">%48</span>)
  <span class="Identifier">%rax_returned</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%67</span>, <span class="Constant">0</span>
  <span class="Identifier">%rdx_returned</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%67</span>, <span class="Constant">1</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rdx_returned</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">2</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rsp_88</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%68</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_88</span>, <span class="Constant">-8</span>
  <span class="Identifier">%69</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%68</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1623</span>, <span class="Type">i64</span>* <span class="Identifier">%69</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">49</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%68</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rax_returned</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">i8</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">20</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">48</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@printf</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x657.exit&quot;</span>

<span class="Constant">&quot;0x657.exit&quot;</span>:                                     <span class="Comment">; preds = %&quot;0x649&quot;, %&quot;0x638&quot;</span>
  <span class="Identifier">%rsp_.0</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x5dd&quot;</span>

<span class="Constant">&quot;0x5dd&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x65b&quot;, %&quot;0x657.exit&quot;, %&quot;0x634&quot;</span>
  <span class="Identifier">%rsp_.1</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Identifier">%rsp_.0</span>, %<span class="Constant">&quot;0x657.exit&quot;</span> ], [ <span class="Identifier">%rsp_52</span>, %<span class="Constant">&quot;0x634&quot;</span> ], [ <span class="Identifier">%rsp_52</span>, %<span class="Constant">&quot;0x65b&quot;</span> ]
  <span class="Identifier">%rax_.0</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Constant">0</span>, %<span class="Constant">&quot;0x657.exit&quot;</span> ], [ <span class="Constant">1</span>, %<span class="Constant">&quot;0x634&quot;</span> ], [ <span class="Constant">1</span>, %<span class="Constant">&quot;0x65b&quot;</span> ]
  <span class="Identifier">%70</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">8</span>
  <span class="Identifier">%71</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">32</span>
  <span class="Identifier">%72</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">24</span>
  <span class="Identifier">%73</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">16</span>
  <span class="Identifier">%74</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.1</span>, <span class="Constant">48</span>
  <span class="Identifier">%75</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%71</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%76</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%75</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%77</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%72</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%78</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%77</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%79</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%73</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%80</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%79</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%81</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%70</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Identifier">%82</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Identifier">%81</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">9</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%70</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">8</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%48</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">1</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%82</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%74</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%80</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%78</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">12</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%76</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">13</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%83</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span> } <span class="Constant">undef</span>, <span class="Type">i64</span> <span class="Identifier">%rax_.0</span>, <span class="Constant">0</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span> } <span class="Identifier">%83</span>

<span class="Constant">&quot;0x68f&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x630&quot;</span>
  <span class="Identifier">%84</span> = <span class="Statement">add</span> <span class="Statement">nsw</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Constant">-45</span>
  <span class="Identifier">%85</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_52</span>, <span class="Constant">-8</span>
  <span class="Identifier">%86</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%85</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1693</span>, <span class="Type">i64</span>* <span class="Identifier">%86</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">14</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%84</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">45</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%85</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%87</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_sub</span>(<span class="Type">i64</span> <span class="Identifier">%r12_54</span>, <span class="Type">i64</span> <span class="Identifier">%rbp_53</span>, <span class="Type">i64</span> <span class="Identifier">%r13_55</span>, <span class="Type">i64</span> <span class="Identifier">%48</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x649&quot;</span>

<span class="Constant">&quot;0x649&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x672&quot;, %&quot;0x65f&quot;, %&quot;0x68f&quot;</span>
  <span class="Identifier">%.sink179</span> = <span class="Statement">phi</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } [ <span class="Identifier">%98</span>, %<span class="Constant">&quot;0x672&quot;</span> ], [ <span class="Identifier">%95</span>, %<span class="Constant">&quot;0x65f&quot;</span> ], [ <span class="Identifier">%87</span>, %<span class="Constant">&quot;0x68f&quot;</span> ]
  <span class="Identifier">%rax_returned159</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%.sink179</span>, <span class="Constant">0</span>
  <span class="Identifier">%rdx_returned160</span> = <span class="Statement">extractvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%.sink179</span>, <span class="Constant">1</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rdx_returned160</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">2</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rsp_161</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%88</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_161</span>, <span class="Constant">-8</span>
  <span class="Identifier">%89</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%88</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1623</span>, <span class="Type">i64</span>* <span class="Identifier">%89</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">49</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%88</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rax_returned159</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">i8</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">20</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">48</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@printf</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x657.exit&quot;</span>

<span class="Constant">&quot;0x65b&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x62e&quot;</span>
  <span class="Identifier">%fold168</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%52</span>, <span class="Constant">214</span>
  <span class="Identifier">%90</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%fold168</span>, <span class="Constant">255</span>
  <span class="Identifier">%91</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%90</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%91</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x65f&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x5dd&quot;</span>

<span class="Constant">&quot;0x65f&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x65b&quot;</span>
  <span class="Identifier">%92</span> = <span class="Statement">add</span> <span class="Statement">nsw</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Constant">-42</span>
  <span class="Identifier">%93</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_52</span>, <span class="Constant">-8</span>
  <span class="Identifier">%94</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%93</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1645</span>, <span class="Type">i64</span>* <span class="Identifier">%94</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">14</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%92</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">42</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%93</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%95</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_mul</span>(<span class="Type">i64</span> <span class="Identifier">%r12_54</span>, <span class="Type">i64</span> <span class="Identifier">%rbp_53</span>, <span class="Type">i64</span> <span class="Identifier">%r13_55</span>, <span class="Type">i64</span> <span class="Identifier">%48</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x649&quot;</span>

<span class="Constant">&quot;0x672&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x5e8&quot;</span>
  <span class="Identifier">%96</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_52</span>, <span class="Constant">-8</span>
  <span class="Identifier">%97</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%96</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1664</span>, <span class="Type">i64</span>* <span class="Identifier">%97</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">14</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%54</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">43</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%53</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">0</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%96</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%98</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_add</span>(<span class="Type">i64</span> <span class="Identifier">%r12_54</span>, <span class="Type">i64</span> <span class="Identifier">%rbp_53</span>, <span class="Type">i64</span> <span class="Identifier">%r13_55</span>, <span class="Type">i64</span> <span class="Identifier">%48</span>)
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x649&quot;</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span> } <span class="Identifier">@register_tm_clones</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x720&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-8</span>
  <span class="Identifier">%1</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%0</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbp_2</span>, <span class="Type">i64</span>* <span class="Identifier">%1</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">41</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@llvm.memset.p0i8.i64</span>(<span class="Type">i8</span>* <span class="Statement">bitcast</span> (<span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>) <span class="Statement">to</span> <span class="Type">i8</span>*), <span class="Type">i8</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">16</span>, <span class="Type">i32</span> <span class="Constant">8</span>, <span class="Type">i1</span> <span class="Constant">false</span>)
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Identifier">%struct.__jove__bss</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">30</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span> } <span class="Constant">zeroinitializer</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span> } <span class="Identifier">@deregister_tm_clones</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x6e0&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-8</span>
  <span class="Identifier">%1</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%0</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbp_2</span>, <span class="Type">i64</span>* <span class="Identifier">%1</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">17</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Identifier">%struct.__jove__bss</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">30</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Identifier">%struct.__jove__bss</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">30</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span> } { <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Identifier">%struct.__jove__bss</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">30</span>) <span class="Statement">to</span> <span class="Type">i64</span>) }
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> <span class="Type">void</span> <span class="Identifier">@_fini</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x8c4&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">9</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">8</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> <span class="Type">void</span> <span class="Identifier">@__do_global_dtors_aux</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x770&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">bitcast</span> (<span class="Identifier">%struct.__jove__bss</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">30</span>) <span class="Statement">to</span> <span class="Type">i64</span>*), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%1</span> = <span class="Statement">and</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Constant">255</span>
  <span class="Identifier">%2</span> = <span class="Statement">icmp</span> <span class="Statement">eq</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Constant">0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Identifier">%2</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x779&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x7a8.exit&quot;</span>

<span class="Constant">&quot;0x779&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x770&quot;</span>
  <span class="Identifier">%rbp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%3</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-8</span>
  <span class="Identifier">%4</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%3</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbp_2</span>, <span class="Type">i64</span>* <span class="Identifier">%4</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">br</span> <span class="Type">i1</span> <span class="Statement">icmp</span> <span class="Statement">eq</span> (<span class="Type">void</span> ()* <span class="Identifier">@__cxa_finalize</span>, <span class="Type">void</span> ()* <span class="Constant">null</span>), <span class="Type">label</span> %<span class="Constant">&quot;0x793&quot;</span>, <span class="Type">label</span> %<span class="Constant">&quot;0x787&quot;</span>

<span class="Constant">&quot;0x787&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x779&quot;</span>
  <span class="Identifier">%5</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-16</span>
  <span class="Identifier">%6</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%5</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1939</span>, <span class="Type">i64</span>* <span class="Identifier">%6</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">17</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">void</span> ()* <span class="Identifier">@__cxa_finalize</span> <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%5</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%3</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">i64</span>** <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">29</span>, <span class="Type">i32</span> <span class="Constant">1</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* <span class="Identifier">@__cxa_finalize</span>)
  <span class="Identifier">%rsp_16</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">br</span> <span class="Type">label</span> %<span class="Constant">&quot;0x793&quot;</span>

<span class="Constant">&quot;0x793&quot;</span>:                                          <span class="Comment">; preds = %&quot;0x787&quot;, %&quot;0x779&quot;</span>
  <span class="Identifier">%rsp_.0</span> = <span class="Statement">phi</span> <span class="Type">i64</span> [ <span class="Identifier">%rsp_16</span>, %<span class="Constant">&quot;0x787&quot;</span> ], [ <span class="Identifier">%3</span>, %<span class="Constant">&quot;0x779&quot;</span> ]
  <span class="Identifier">%7</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_.0</span>, <span class="Constant">-8</span>
  <span class="Identifier">%8</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%7</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">1944</span>, <span class="Type">i64</span>* <span class="Identifier">%8</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">17</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Type">void</span> ()* <span class="Identifier">@__cxa_finalize</span> <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%7</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%3</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%9</span> = <span class="Statement">tail</span> <span class="Statement">call</span> { <span class="Type">i64</span> } <span class="Identifier">@deregister_tm_clones</span>()
  <span class="Statement">unreachable</span>

<span class="Constant">&quot;0x7a8.exit&quot;</span>:                                     <span class="Comment">; preds = %&quot;0x770&quot;</span>
  <span class="Identifier">%10</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">14</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%10</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> <span class="Type">void</span> <span class="Identifier">@__libc_csu_fini</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x8c0&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span> } <span class="Identifier">@frame_dummy</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x7b0&quot;</span>:
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%rbp_2</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">5</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%0</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">-8</span>
  <span class="Identifier">%1</span> = <span class="Statement">inttoptr</span> <span class="Type">i64</span> <span class="Identifier">%0</span> <span class="Statement">to</span> <span class="Type">i64</span>*
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rbp_2</span>, <span class="Type">i64</span>* <span class="Identifier">%1</span>, <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!noalias</span> <span class="Identifier">!0</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">41</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@llvm.memset.p0i8.i64</span>(<span class="Type">i8</span>* <span class="Statement">bitcast</span> (<span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>) <span class="Statement">to</span> <span class="Type">i8</span>*), <span class="Type">i8</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">16</span>, <span class="Type">i32</span> <span class="Constant">8</span>, <span class="Type">i1</span> <span class="Constant">false</span>)
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Statement">ptrtoint</span> (<span class="Identifier">%struct.__jove__bss</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.__jove_sections</span>, <span class="Identifier">%struct.__jove_sections</span>* <span class="Identifier">@__jove_sections</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">30</span>) <span class="Statement">to</span> <span class="Type">i64</span>), <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">7</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span> } <span class="Constant">zeroinitializer</span>
}

<span class="Comment">; Function Attrs: noinline norecurse nounwind</span>
<span class="Statement">define</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@cn_sub</span>(<span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span> <span class="Identifier">%rcx</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">1</span> {
<span class="Constant">&quot;0x7d0&quot;</span>:
  <span class="Identifier">%0</span> = <span class="Statement">sub</span> <span class="Type">i64</span> <span class="Identifier">%rsi</span>, <span class="Identifier">%rcx</span>
  <span class="Identifier">%1</span> = <span class="Statement">sub</span> <span class="Type">i64</span> <span class="Identifier">%rdi</span>, <span class="Identifier">%rdx</span>
  <span class="Identifier">%rsp_1</span> = <span class="Statement">load</span> <span class="Type">i64</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%2</span> = <span class="Statement">add</span> <span class="Type">i64</span> <span class="Identifier">%rsp_1</span>, <span class="Constant">8</span>
  <span class="Statement">store</span> <span class="Type">i32</span> <span class="Constant">17</span>, <span class="Type">i32</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">3</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%rdx</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%2</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">4</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Statement">store</span> <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Type">i64</span>* <span class="Statement">getelementptr</span> <span class="Statement">inbounds</span> (<span class="Identifier">%struct.CPUX86State</span>, <span class="Identifier">%struct.CPUX86State</span>* <span class="Identifier">@cpu_state</span>, <span class="Type">i64</span> <span class="Constant">0</span>, <span class="Type">i32</span> <span class="Constant">0</span>, <span class="Type">i64</span> <span class="Constant">6</span>), <span class="Statement">align</span> <span class="Constant">8</span>, <span class="Identifier">!alias.scope</span> <span class="Identifier">!0</span>
  <span class="Identifier">%3</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Constant">undef</span>, <span class="Type">i64</span> <span class="Identifier">%1</span>, <span class="Constant">0</span>
  <span class="Identifier">%4</span> = <span class="Statement">insertvalue</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%3</span>, <span class="Type">i64</span> <span class="Identifier">%0</span>, <span class="Constant">1</span>
  <span class="Statement">ret</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">%4</span>
}

<span class="Comment">; Function Attrs: noinline</span>
<span class="Statement">define</span> <span class="Statement">internal</span> <span class="Type">void</span> @<span class="Constant">&quot;0x580&quot;</span>() <span class="Statement">local_unnamed_addr</span> #<span class="Constant">2</span> {
<span class="Constant">&quot;0x580&quot;</span>:
  <span class="Statement">tail</span> <span class="Statement">call</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()* nonnull <span class="Identifier">@puts</span>)
  <span class="Statement">ret</span> <span class="Type">void</span>
}

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@__jove_indirect_call</span>(<span class="Type">void</span> ()*) <span class="Statement">local_unnamed_addr</span>

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@__jove_indirect_jump</span>(<span class="Type">void</span> ()*) <span class="Statement">local_unnamed_addr</span>

<span class="Comment">; Function Attrs: norecurse nounwind readnone uwtable</span>
<span class="Statement">declare</span> <span class="Type">i64</span> <span class="Identifier">@helper_mulsh_i64</span>(<span class="Type">i64</span>, <span class="Type">i64</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">3</span>

<span class="Comment">; Function Attrs: norecurse nounwind readnone uwtable</span>
<span class="Statement">declare</span> { <span class="Type">i64</span>, <span class="Type">i64</span> } <span class="Identifier">@helper_idivq_EAX</span>(<span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">3</span>

<span class="Comment">; Function Attrs: norecurse nounwind readnone uwtable</span>
<span class="Statement">declare</span> <span class="Type">i64</span> <span class="Identifier">@helper_cc_compute_all</span>(<span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i64</span>, <span class="Type">i32</span>) <span class="Statement">local_unnamed_addr</span> #<span class="Constant">3</span>

<span class="Comment">; Function Attrs: argmemonly nounwind</span>
<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@llvm.memset.p0i8.i64</span>(<span class="Type">i8</span>* <span class="Statement">nocapture</span> <span class="Statement">writeonly</span>, <span class="Type">i8</span>, <span class="Type">i64</span>, <span class="Type">i32</span>, <span class="Type">i1</span>) #<span class="Constant">4</span>

<span class="Statement">declare</span> <span class="Type">void</span> <span class="Identifier">@__jove_call</span>(<span class="Type">void</span> ()*)

attributes #<span class="Constant">0</span> = { <span class="Statement">noinline</span> <span class="Statement">noreturn</span> }
attributes #<span class="Constant">1</span> = { <span class="Statement">noinline</span> <span class="Statement">norecurse</span> <span class="Statement">nounwind</span> }
attributes #<span class="Constant">2</span> = { <span class="Statement">noinline</span> }
attributes #<span class="Constant">3</span> = { <span class="Statement">norecurse</span> <span class="Statement">nounwind</span> <span class="Statement">readnone</span> <span class="Statement">uwtable</span> <span class="Constant">&quot;correctly-rounded-divide-sqrt-fp-math&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;disable-tail-calls&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;less-precise-fpmad&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;no-frame-pointer-elim&quot;</span>=<span class="Constant">&quot;true&quot;</span> <span class="Constant">&quot;no-frame-pointer-elim-non-leaf&quot;</span> <span class="Constant">&quot;no-infs-fp-math&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;no-jump-tables&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;no-nans-fp-math&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;no-signed-zeros-fp-math&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;no-trapping-math&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;stack-protector-buffer-size&quot;</span>=<span class="Constant">&quot;8&quot;</span> <span class="Constant">&quot;target-cpu&quot;</span>=<span class="Constant">&quot;x86-64&quot;</span> <span class="Constant">&quot;target-features&quot;</span>=<span class="Constant">&quot;+fxsr,+mmx,+sse,+sse2,+x87&quot;</span> <span class="Constant">&quot;unsafe-fp-math&quot;</span>=<span class="Constant">&quot;false&quot;</span> <span class="Constant">&quot;use-soft-float&quot;</span>=<span class="Constant">&quot;false&quot;</span> }
attributes #<span class="Constant">4</span> = { <span class="Statement">argmemonly</span> <span class="Statement">nounwind</span> }

<span class="Identifier">!0</span> = !{<span class="Identifier">!1</span>}
<span class="Identifier">!1</span> = !{!<span class="Constant">&quot;JoveScope&quot;</span>, <span class="Identifier">!2</span>}
<span class="Identifier">!2</span> = !{!<span class="Constant">&quot;JoveDomain&quot;</span>}
</pre>
</body>
</html>
<!-- vim: set foldmethod=manual : -->
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

Translating arm machine code to QEMU IR...

ARM code @ 598 call_weak_fn
Thumb code @ 5bc deregister_tm_clones
Thumb code @ 5ec register_tm_clones
Thumb code @ 620 __do_global_dtors_aux
Thumb code @ 660 frame_dummy
Thumb code @ 758 __divsi3
Thumb code @ 758 __aeabi_idiv
Thumb code @ 9ec __aeabi_idivmod
Thumb code @ a08 __aeabi_idiv0
Thumb code @ a08 __aeabi_ldiv0
Thumb code @ a54 __libc_csu_fini
Thumb code @ 550 _start
Thumb code @ a14 __libc_csu_init
Thumb code @ 490 main
ARM code @ 40c _init
ARM code @ a58 _fini
Thumb code @ 68c cn_add
Thumb code @ 6b0 cn_sub
Thumb code @ 6d4 cn_mul
Thumb code @ 704 cn_div
6d4
  6d4
    note: return
660
  660
    note: conditional jump to 674 and 66e
  674
    note: conditional jump to 66e and 67c
  66e
    note: unconditional jump to 5ec
  5ec
    note: conditional jump to 60c and 604
  60c
    note: return
  604
    note: conditional jump to 60c and 60a
  60a
    note: indirect jump
  67c
    note: indirect call
  67e
    note: unconditional jump to 66e
550
  550
    note: direct call to 42c
  584
    note: direct call to 438
  588
    note: invalid instruction @ 588 (THUMB)
620
  620
    note: conditional jump to 64a and 62e
  64a
    note: return
  62e
    note: conditional jump to 63e and 634
  63e
    note: direct call to 5bc
  642
    note: return
  634
    note: direct call to 450
758
  758
    note: conditional jump to 9da and 75e
  9da
    note: unconditional jump to a08
  a08
    note: direct call to 480
  a12
    note: return
  75e
    note: conditional jump to 9aa and 76c
  9aa
    note: return
  76c
    note: conditional jump to 9b4 and 778
  9b4
    note: return
  778
    note: conditional jump to 9c4 and 77e
  9c4
    note: return
  77e
    note: return
68c
  68c
    note: return
598
  598
    note: unconditional jump to 5b0
  5b0
    note: unconditional jump to 444
  444
    note: return
5bc
  5bc
    note: conditional jump to 5d8 and 5d0
  5d8
    note: return
  5d0
    note: conditional jump to 5d8 and 5d6
  5d6
    note: indirect jump
9ec
  9ec
    note: conditional jump to 9da and 9f0
  9da
    note: unconditional jump to a08
  a08
    note: direct call to 480
  a12
    note: return
  9f0
    note: direct call to 75e
  9f8
    note: return
a08
  a08
    note: direct call to 480
  a12
    note: return
a54
  a54
    note: return
a14
  a14
    note: direct call to 40c
  a28
    note: conditional jump to a46 and a30
  a46
    note: return
  a30
    note: indirect call
  a42
    note: conditional jump to a34 and a46
  a34
    note: indirect call
490
  490
    note: conditional jump to 4a6 and 498
  4a6
    note: direct call to 468
  4b2
    note: direct call to 468
  4be
    note: direct call to 468
  4ca
    note: direct call to 468
  4d6
    note: conditional jump to 542 and 4e2
  542
    note: unconditional jump to 4a2
  4a2
    note: return
  4e2
    note: indirect jump
  498
    note: direct call to 45c
  4a0
    note: return
704
  704
    note: direct call to 758
  736
    note: direct call to 758
  748
    note: return
a58
  a58
    note: return
6b0
  6b0
    note: return
5ec
  5ec
    note: conditional jump to 60c and 604
  60c
    note: return
  604
    note: conditional jump to 60c and 60a
  60a
    note: indirect jump
40c
  40c
    note: direct call to 598
  414
    note: return
42c
  42c
    note: return
438
  438
    note: return
450
  450
    note: return
480
  480
    note: return
75e
  75e
    note: invalid instruction @ 75e (ARM)
468
  468
    note: return
45c
  45c
    note: return

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
; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_add(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
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

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_sub(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
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

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_mul(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
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

; Function Attrs: noinline nounwind
define internal { i32 } @cn_div(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #2 {
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
  store i32 1847, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
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
  store i32 1865, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
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
  store i32 %56, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
  %59 = insertvalue { i32 } undef, i32 %r8_22, 0
  ret { i32 } %59
}

; Function Attrs: noinline nounwind
define internal { i32, i32 } @__aeabi_idiv(i32 %r0, i32 %r1) local_unnamed_addr #2 {
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
  store i32 2579, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 14), align 4, !alias.scope !0
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
  br i1 %34, label %"0x9c4", label %"0x77e.exit"

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

"0x77e.exit":                                     ; preds = %"0x778"
  %47 = tail call i32 @helper_clz(i32 %r0.39)
  %48 = tail call i32 @helper_clz(i32 %r1.)
  %49 = sub i32 %47, %48
  %50 = shl i32 %49, 4
  %51 = add i32 %50, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i32 0, i32 15, i32 0, i32 1280) to i32)
  store i32 %51, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 2), align 4, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 3), align 4, !alias.scope !0
  store i32 %13, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 12), align 4, !alias.scope !0
  store i32 %33, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 14), align 4, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 13), align 4, !alias.scope !0
  store i32 %33, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i32 0, i32 15), align 4, !alias.scope !0
  %52 = insertvalue { i32, i32 } { i32 0, i32 undef }, i32 %r1., 1
  ret { i32, i32 } %52

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
