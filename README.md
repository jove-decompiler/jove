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
### Machine Code
#### AAarch64
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
### Decompilation
#### AAarch64
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
```llvm
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
