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
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  %r13_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %r14_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %0 = add i32 %r13_3, -16
  %1 = zext i32 %0 to i64
  %2 = inttoptr i64 %1 to i32*
  store i32 %r4_1, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_3, -12
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i32*
  store i32 %r5_2, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_3, -24
  %7 = add i32 %r13_3, -4
  %8 = zext i32 %7 to i64
  %9 = inttoptr i64 %8 to i32*
  store i32 %r3, i32* %9, align 4, !noalias !0
  %10 = zext i32 %6 to i64
  %11 = inttoptr i64 %10 to i32*
  store i32 %r1, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_3, -20
  %13 = zext i32 %12 to i64
  %14 = inttoptr i64 %13 to i32*
  store i32 %r2, i32* %14, align 4, !noalias !0
  %15 = zext i32 %r13_3 to i64
  %16 = inttoptr i64 %15 to i32*
  %17 = load i32, i32* %16, align 4, !noalias !0
  %18 = load i32, i32* %11, align 4, !noalias !0
  %19 = add i32 %17, %r2
  %20 = add i32 %r0, 4
  %21 = zext i32 %20 to i64
  %22 = inttoptr i64 %21 to i32*
  store i32 %19, i32* %22, align 4, !noalias !0
  %23 = add i32 %18, %r3
  %24 = zext i32 %r0 to i64
  %25 = inttoptr i64 %24 to i32*
  store i32 %23, i32* %25, align 4, !noalias !0
  %26 = load i32, i32* %2, align 4, !noalias !0
  %27 = load i32, i32* %5, align 4, !noalias !0
  %28 = and i32 %r14_4, 1
  store i32 %28, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  store i32 %18, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %23, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 3), align 4, !alias.scope !0
  store i32 %26, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  %29 = insertvalue { i32 } undef, i32 %19, 0
  ret { i32 } %29
}

; Function Attrs: noinline nounwind
define internal { i32, i32 } @__aeabi_idiv(i32 %r0, i32 %r1) local_unnamed_addr #2 {
"0x758":
  %r13_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %r14_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %0 = icmp eq i32 %r1, 0
  br i1 %0, label %"0xa08", label %"0x75e"

"0xa08":                                          ; preds = %"0x758"
  %1 = add i32 %r13_1, -8
  %2 = zext i32 %1 to i64
  %3 = inttoptr i64 %2 to i32*
  store i32 0, i32* %3, align 4, !noalias !0
  %4 = add i32 %r13_1, -4
  %5 = zext i32 %4 to i64
  %6 = inttoptr i64 %5 to i32*
  store i32 %r14_2, i32* %6, align 4, !noalias !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  store i32 8, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 0), align 8, !alias.scope !0
  store i32 %1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  store i32 2579, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  tail call void @"0x480"()
  %r13_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %7 = zext i32 %r13_8 to i64
  %8 = inttoptr i64 %7 to i32*
  %9 = load i32, i32* %8, align 4, !noalias !0
  %10 = add i32 %r13_8, 4
  %11 = zext i32 %10 to i64
  %12 = inttoptr i64 %11 to i32*
  %13 = load i32, i32* %12, align 4, !noalias !0
  %14 = and i32 %13, 1
  store i32 %14, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  %15 = add i32 %r13_8, 8
  store i32 %15, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  %16 = insertvalue { i32, i32 } { i32 8, i32 undef }, i32 %9, 1
  ret { i32, i32 } %16

"0x75e":                                          ; preds = %"0x758"
  %17 = xor i32 %r1, %r0
  %18 = icmp sgt i32 %r1, -1
  %19 = sub i32 0, %r1
  %r1. = select i1 %18, i32 %r1, i32 %19
  %20 = add i32 %r1., -1
  %21 = icmp eq i32 %20, 0
  br i1 %21, label %"0x9aa", label %"0x76c"

"0x9aa":                                          ; preds = %"0x75e"
  %22 = and i32 %r1., -2
  %23 = sub i32 0, %r0
  %r0. = select i1 %18, i32 %r0, i32 %23
  %24 = and i32 %r14_2, 1
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %22, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %r1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  %25 = insertvalue { i32, i32 } undef, i32 %r0., 0
  %26 = insertvalue { i32, i32 } %25, i32 %r1., 1
  ret { i32, i32 } %26

"0x76c":                                          ; preds = %"0x75e"
  %27 = icmp sgt i32 %r0, -1
  %28 = sub i32 0, %r0
  %r0.39 = select i1 %27, i32 %r0, i32 %28
  %29 = sub i32 %r0.39, %r1.
  %30 = icmp uge i32 %r0.39, %r1.
  %31 = zext i1 %30 to i32
  %32 = xor i32 %29, %r0.39
  %33 = xor i32 %r1., %r0.39
  %34 = and i32 %32, %33
  %35 = icmp ne i32 %29, 0
  %36 = and i1 %30, %35
  br i1 %36, label %"0x778", label %l324

"0x778":                                          ; preds = %"0x76c"
  %37 = and i32 %20, %r1.
  %38 = icmp eq i32 %37, 0
  br i1 %38, label %"0x9c4", label %"0x77e.exit"

"0x9c4":                                          ; preds = %"0x778"
  %39 = tail call i32 @helper_clz(i32 %r1.)
  %40 = sub i32 31, %39
  %41 = and i32 %40, 224
  %42 = icmp ult i32 %41, 32
  %43 = select i1 %42, i32 %r0.39, i32 0
  %44 = and i32 %40, 31
  %45 = lshr i32 %43, %44
  %46 = icmp sgt i32 %17, -1
  %47 = sub i32 0, %45
  %.41 = select i1 %46, i32 %45, i32 %47
  %48 = and i32 %r14_2, 1
  store i32 %48, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  store i32 %40, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 3), align 4, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i32 1, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  %49 = insertvalue { i32, i32 } undef, i32 %.41, 0
  %50 = insertvalue { i32, i32 } %49, i32 %r1., 1
  ret { i32, i32 } %50

"0x77e.exit":                                     ; preds = %"0x778"
  %51 = tail call i32 @helper_clz(i32 %r0.39)
  %52 = tail call i32 @helper_clz(i32 %r1.)
  %53 = sub i32 %51, %52
  %54 = shl i32 %53, 4
  %55 = add i32 %54, ptrtoint (i8* getelementptr inbounds (%struct.__jove_sections, %struct.__jove_sections* @__jove_sections, i64 0, i32 15, i32 0, i64 1280) to i32)
  store i32 %55, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 3), align 4, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i32 %31, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %37, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %34, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %37, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  %56 = insertvalue { i32, i32 } { i32 0, i32 undef }, i32 %r1., 1
  ret { i32, i32 } %56

l324:                                             ; preds = %"0x76c"
  %r0_.1 = select i1 %30, i32 %r0, i32 0
  %57 = icmp eq i32 %29, 0
  %58 = ashr i32 %17, 31
  %59 = or i32 %58, 1
  %..r0_.1 = select i1 %57, i32 %59, i32 %r0_.1
  %60 = and i32 %r14_2, 1
  store i32 %60, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %r0.39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 3), align 4, !alias.scope !0
  store i32 %17, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 12), align 8, !alias.scope !0
  store i32 %31, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %34, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %29, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  %61 = insertvalue { i32, i32 } undef, i32 %..r0_.1, 0
  %62 = insertvalue { i32, i32 } %61, i32 %r1., 1
  ret { i32, i32 } %62
}

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_mul(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
"0x6d4":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  %r6_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  %r7_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 7), align 4, !alias.scope !0
  %r13_5 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %r14_6 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %0 = add i32 %r13_5, -24
  %1 = zext i32 %0 to i64
  %2 = inttoptr i64 %1 to i32*
  store i32 %r4_1, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_5, -20
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i32*
  store i32 %r5_2, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_5, -16
  %7 = zext i32 %6 to i64
  %8 = inttoptr i64 %7 to i32*
  store i32 %r6_3, i32* %8, align 4, !noalias !0
  %9 = add i32 %r13_5, -12
  %10 = zext i32 %9 to i64
  %11 = inttoptr i64 %10 to i32*
  store i32 %r7_4, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_5, -32
  %13 = add i32 %r13_5, -4
  %14 = zext i32 %13 to i64
  %15 = inttoptr i64 %14 to i32*
  store i32 %r3, i32* %15, align 4, !noalias !0
  %16 = zext i32 %12 to i64
  %17 = inttoptr i64 %16 to i32*
  store i32 %r1, i32* %17, align 4, !noalias !0
  %18 = add i32 %r13_5, -28
  %19 = zext i32 %18 to i64
  %20 = inttoptr i64 %19 to i32*
  store i32 %r2, i32* %20, align 4, !noalias !0
  %21 = load i32, i32* %17, align 4, !noalias !0
  %22 = zext i32 %r13_5 to i64
  %23 = inttoptr i64 %22 to i32*
  %24 = load i32, i32* %23, align 4, !noalias !0
  %25 = mul i32 %21, %r3
  %26 = mul i32 %24, %21
  %27 = mul i32 %r3, %r2
  %28 = add i32 %26, %27
  %29 = mul i32 %24, %r2
  %30 = sub i32 %25, %29
  %31 = add i32 %r0, 4
  %32 = zext i32 %31 to i64
  %33 = inttoptr i64 %32 to i32*
  store i32 %28, i32* %33, align 4, !noalias !0
  %34 = zext i32 %r0 to i64
  %35 = inttoptr i64 %34 to i32*
  store i32 %30, i32* %35, align 4, !noalias !0
  %36 = load i32, i32* %2, align 4, !noalias !0
  %37 = load i32, i32* %5, align 4, !noalias !0
  %38 = load i32, i32* %8, align 4, !noalias !0
  %39 = load i32, i32* %11, align 4, !noalias !0
  %40 = and i32 %r14_6, 1
  store i32 %40, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  store i32 %30, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %36, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i32 %37, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  store i32 %38, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i32 %39, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 7), align 4, !alias.scope !0
  %41 = insertvalue { i32 } undef, i32 %28, 0
  ret { i32 } %41
}

; Function Attrs: noinline norecurse nounwind
define internal { i32 } @cn_sub(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #0 {
"0x6b0":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  %r13_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %r14_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %0 = add i32 %r13_3, -16
  %1 = zext i32 %0 to i64
  %2 = inttoptr i64 %1 to i32*
  store i32 %r4_1, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_3, -12
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i32*
  store i32 %r5_2, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_3, -24
  %7 = zext i32 %r13_3 to i64
  %8 = inttoptr i64 %7 to i32*
  %9 = load i32, i32* %8, align 4, !noalias !0
  %10 = zext i32 %6 to i64
  %11 = inttoptr i64 %10 to i32*
  store i32 %r1, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_3, -20
  %13 = zext i32 %12 to i64
  %14 = inttoptr i64 %13 to i32*
  store i32 %r2, i32* %14, align 4, !noalias !0
  %15 = load i32, i32* %11, align 4, !noalias !0
  %16 = add i32 %r13_3, -4
  %17 = zext i32 %16 to i64
  %18 = inttoptr i64 %17 to i32*
  store i32 %r3, i32* %18, align 4, !noalias !0
  %19 = sub i32 %r2, %9
  %20 = sub i32 %15, %r3
  %21 = add i32 %r0, 4
  %22 = zext i32 %21 to i64
  %23 = inttoptr i64 %22 to i32*
  store i32 %19, i32* %23, align 4, !noalias !0
  %24 = zext i32 %r0 to i64
  %25 = inttoptr i64 %24 to i32*
  store i32 %20, i32* %25, align 4, !noalias !0
  %26 = load i32, i32* %2, align 4, !noalias !0
  %27 = load i32, i32* %5, align 4, !noalias !0
  %28 = and i32 %r14_4, 1
  store i32 %28, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  %29 = xor i32 %20, %15
  %30 = xor i32 %15, %r3
  %31 = and i32 %29, %30
  %32 = icmp uge i32 %15, %r3
  %33 = zext i1 %32 to i32
  store i32 %15, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 2), align 8, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 3), align 4, !alias.scope !0
  store i32 %26, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i32 %27, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  store i32 %33, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 12), align 8, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 14), align 8, !alias.scope !0
  store i32 %31, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 13), align 4, !alias.scope !0
  store i32 %20, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 15), align 4, !alias.scope !0
  %34 = insertvalue { i32 } undef, i32 %19, 0
  ret { i32 } %34
}

; Function Attrs: noinline nounwind
define internal { i32 } @cn_div(i32 %r0, i32 %r1, i32 %r2, i32 %r3) local_unnamed_addr #2 {
"0x704":
  %r4_1 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %r5_2 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  %r6_3 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  %r7_4 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 7), align 4, !alias.scope !0
  %r8_5 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  %r9_6 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 9), align 4, !alias.scope !0
  %r13_7 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %r14_8 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %0 = add i32 %r13_7, -36
  %1 = zext i32 %0 to i64
  %2 = inttoptr i64 %1 to i32*
  store i32 %r4_1, i32* %2, align 4, !noalias !0
  %3 = add i32 %r13_7, -32
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i32*
  store i32 %r5_2, i32* %5, align 4, !noalias !0
  %6 = add i32 %r13_7, -28
  %7 = zext i32 %6 to i64
  %8 = inttoptr i64 %7 to i32*
  store i32 %r6_3, i32* %8, align 4, !noalias !0
  %9 = add i32 %r13_7, -24
  %10 = zext i32 %9 to i64
  %11 = inttoptr i64 %10 to i32*
  store i32 %r7_4, i32* %11, align 4, !noalias !0
  %12 = add i32 %r13_7, -20
  %13 = zext i32 %12 to i64
  %14 = inttoptr i64 %13 to i32*
  store i32 %r8_5, i32* %14, align 4, !noalias !0
  %15 = add i32 %r13_7, -16
  %16 = zext i32 %15 to i64
  %17 = inttoptr i64 %16 to i32*
  store i32 %r9_6, i32* %17, align 4, !noalias !0
  %18 = add i32 %r13_7, -12
  %19 = zext i32 %18 to i64
  %20 = inttoptr i64 %19 to i32*
  store i32 %r14_8, i32* %20, align 4, !noalias !0
  %21 = add i32 %r13_7, -48
  %22 = zext i32 %r13_7 to i64
  %23 = inttoptr i64 %22 to i32*
  %24 = load i32, i32* %23, align 4, !noalias !0
  %25 = zext i32 %21 to i64
  %26 = inttoptr i64 %25 to i32*
  store i32 %r1, i32* %26, align 4, !noalias !0
  %27 = add i32 %r13_7, -44
  %28 = zext i32 %27 to i64
  %29 = inttoptr i64 %28 to i32*
  store i32 %r2, i32* %29, align 4, !noalias !0
  %30 = mul i32 %24, %24
  %31 = load i32, i32* %26, align 4, !noalias !0
  %32 = mul i32 %r3, %r3
  %33 = add i32 %30, %32
  %34 = add i32 %r13_7, -4
  %35 = zext i32 %34 to i64
  %36 = inttoptr i64 %35 to i32*
  store i32 %r3, i32* %36, align 4, !noalias !0
  %37 = mul i32 %31, %r3
  %38 = mul i32 %24, %r2
  %39 = add i32 %37, %38
  store i32 %24, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i32 %r2, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  store i32 %33, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i32 %r3, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 7), align 4, !alias.scope !0
  store i32 %r0, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  store i32 %31, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 9), align 4, !alias.scope !0
  store i32 %21, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  store i32 1847, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %40 = tail call { i32, i32 } @__aeabi_idiv(i32 %39, i32 %33)
  %r1_returned = extractvalue { i32, i32 } %40, 1
  store i32 %r1_returned, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 1), align 4, !alias.scope !0
  %r6_11 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  %r9_14 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 9), align 4, !alias.scope !0
  %r8_13 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  %r7_12 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 7), align 4, !alias.scope !0
  %r5_10 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  %r4_9 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  %r0_returned = extractvalue { i32, i32 } %40, 0
  %41 = mul i32 %r5_10, %r7_12
  %42 = zext i32 %r8_13 to i64
  %43 = inttoptr i64 %42 to i32*
  store i32 %r0_returned, i32* %43, align 4, !noalias !0
  %44 = mul i32 %r4_9, %r9_14
  %45 = sub i32 %41, %44
  store i32 %41, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  store i32 1865, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %46 = tail call { i32, i32 } @__aeabi_idiv(i32 %45, i32 %r6_11)
  %r1_returned21 = extractvalue { i32, i32 } %46, 1
  store i32 %r1_returned21, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 1), align 4, !alias.scope !0
  %r8_22 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  %r13_23 = load i32, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  %r0_returned20 = extractvalue { i32, i32 } %46, 0
  %47 = add i32 %r8_22, 4
  %48 = zext i32 %47 to i64
  %49 = inttoptr i64 %48 to i32*
  store i32 %r0_returned20, i32* %49, align 4, !noalias !0
  %50 = add i32 %r13_23, 12
  %51 = zext i32 %50 to i64
  %52 = inttoptr i64 %51 to i32*
  %53 = load i32, i32* %52, align 4, !noalias !0
  %54 = add i32 %r13_23, 16
  %55 = zext i32 %54 to i64
  %56 = inttoptr i64 %55 to i32*
  %57 = load i32, i32* %56, align 4, !noalias !0
  %58 = add i32 %r13_23, 20
  %59 = zext i32 %58 to i64
  %60 = inttoptr i64 %59 to i32*
  %61 = load i32, i32* %60, align 4, !noalias !0
  %62 = add i32 %r13_23, 24
  %63 = zext i32 %62 to i64
  %64 = inttoptr i64 %63 to i32*
  %65 = load i32, i32* %64, align 4, !noalias !0
  %66 = add i32 %r13_23, 28
  %67 = zext i32 %66 to i64
  %68 = inttoptr i64 %67 to i32*
  %69 = load i32, i32* %68, align 4, !noalias !0
  %70 = add i32 %r13_23, 32
  %71 = zext i32 %70 to i64
  %72 = inttoptr i64 %71 to i32*
  %73 = load i32, i32* %72, align 4, !noalias !0
  %74 = add i32 %r13_23, 36
  %75 = zext i32 %74 to i64
  %76 = inttoptr i64 %75 to i32*
  %77 = load i32, i32* %76, align 4, !noalias !0
  %78 = and i32 %77, 1
  store i32 %78, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 18), align 8, !alias.scope !0
  %79 = add i32 %r13_23, 48
  store i32 %53, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 4), align 8, !alias.scope !0
  store i32 %57, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 5), align 4, !alias.scope !0
  store i32 %61, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 6), align 8, !alias.scope !0
  store i32 %65, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 7), align 4, !alias.scope !0
  store i32 %69, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 8), align 8, !alias.scope !0
  store i32 %73, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 9), align 4, !alias.scope !0
  store i32 %79, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 13), align 4, !alias.scope !0
  store i32 %77, i32* getelementptr inbounds (%struct.CPUARMState, %struct.CPUARMState* @cpu_state, i64 0, i32 0, i64 14), align 8, !alias.scope !0
  %80 = insertvalue { i32 } undef, i32 %r8_22, 0
  ret { i32 } %80
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
