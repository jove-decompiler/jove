#include "sjlj.h"
#include "B.h"

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/raw_ostream.h>

using llvm::WithColor;

namespace obj = llvm::object;

namespace jove {

template <bool MT, bool MinSize>
void ScanForSjLj(binary_base_t<MT, MinSize> &b,
                 llvm::object::Binary &Bin,
                 explorer_t<MT, MinSize> &E) {
  std::vector<std::pair<llvm::StringRef, int>> LjPatterns;
  std::vector<llvm::StringRef> SjPatterns;

#if defined(TARGET_X86_64)
  {
    // glibc
    static const uint8_t pattern[] = {
      0x4c, 0x8b, 0x47, 0x30,                   // mov    0x30(%rdi),%r8
      0x4c, 0x8b, 0x4f, 0x08,                   // mov    0x8(%rdi),%r9
      0x48, 0x8b, 0x57, 0x38,                   // mov    0x38(%rdi),%rdx
      0x49, 0xc1, 0xc8, 0x11,                   // ror    $0x11,%r8
      0x64, 0x4c, 0x33, 0x04, 0x25, 0x30, 0x00, // xor    %fs:0x30,%r8
      0x00, 0x00,
      0x49, 0xc1, 0xc9, 0x11,                   // ror    $0x11,%r9
      0x64, 0x4c, 0x33, 0x0c, 0x25, 0x30, 0x00, // xor    %fs:0x30,%r9
      0x00, 0x00,
      0x48, 0xc1, 0xca, 0x11,                   // ror    $0x11,%rdx
      0x64, 0x48, 0x33, 0x14, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rdx
      0x00, 0x00,
      0x48, 0x8b, 0x1f,                         // mov    (%rdi),%rbx
      0x4c, 0x8b, 0x67, 0x10,                   // mov    0x10(%rdi),%r12
      0x4c, 0x8b, 0x6f, 0x18,                   // mov    0x18(%rdi),%r13
      0x4c, 0x8b, 0x77, 0x20,                   // mov    0x20(%rdi),%r14
      0x4c, 0x8b, 0x7f, 0x28,                   // mov    0x28(%rdi),%r15
      0x89, 0xf0,                               // mov    %esi,%eax
      0x4c, 0x89, 0xc4,                         // mov    %r8,%rsp
      0x4c, 0x89, 0xcd,                         // mov    %r9,%rbp
      0xff, 0xe2,                               // jmp    *%rdx
    };

    LjPatterns.emplace_back(
        llvm::StringRef(reinterpret_cast<const char *>(&pattern[0]),
                        sizeof(pattern)),
        0);
  }

  {
    // glibc
    static const uint8_t pattern[] = {
      0x48, 0x89, 0x1f,                         // mov    %rbx,(%rdi)
      0x48, 0x89, 0xe8,                         // mov    %rbp,%rax
      0x64, 0x48, 0x33, 0x04, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rax
      0x00, 0x00,
      0x48, 0xc1, 0xc0, 0x11,                   // rol    $0x11,%rax
      0x48, 0x89, 0x47, 0x08,                   // mov    %rax,0x8(%rdi)
      0x4c, 0x89, 0x67, 0x10,                   // mov    %r12,0x10(%rdi)
      0x4c, 0x89, 0x6f, 0x18,                   // mov    %r13,0x18(%rdi)
      0x4c, 0x89, 0x77, 0x20,                   // mov    %r14,0x20(%rdi)
      0x4c, 0x89, 0x7f, 0x28,                   // mov    %r15,0x28(%rdi)
      0x48, 0x8d, 0x54, 0x24, 0x08,             // lea    0x8(%rsp),%rdx
      0x64, 0x48, 0x33, 0x14, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rdx
      0x00, 0x00,
      0x48, 0xc1, 0xc2, 0x11,                   // rol    $0x11,%rdx
      0x48, 0x89, 0x57, 0x30,                   // mov    %rdx,0x30(%rdi)
      0x48, 0x8b, 0x04, 0x24,                   // mov    (%rsp),%rax
      0x64, 0x48, 0x33, 0x04, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rax
      0x00, 0x00,
      0x48, 0xc1, 0xc0, 0x11,                   // rol    $0x11,%rax
      0x48, 0x89, 0x47, 0x38,                   // mov    %rax,0x38(%rdi)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
#elif defined(TARGET_I386)
  {
    // glibc
    static const uint8_t pattern[] = {
      0x8b, 0x44, 0x24, 0x04,                   //  mov    0x4(%esp),%eax
      0x8b, 0x50, 0x14,                         //  mov    0x14(%eax),%edx
      0x8b, 0x48, 0x10,                         //  mov    0x10(%eax),%ecx
      0xc1, 0xca, 0x09,                         //  ror    $0x9,%edx
      0x65, 0x33, 0x15, 0x18, 0x00, 0x00, 0x00, //  xor    %gs:0x18,%edx
      0xc1, 0xc9, 0x09,                         //  ror    $0x9,%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, //  xor    %gs:0x18,%ecx
      0x8b, 0x18,                               //  mov    (%eax),%ebx
      0x8b, 0x70, 0x04,                         //  mov    0x4(%eax),%esi
      0x8b, 0x78, 0x08,                         //  mov    0x8(%eax),%edi
      0x8b, 0x68, 0x0c,                         //  mov    0xc(%eax),%ebp
      0x8b, 0x44, 0x24, 0x08,                   //  mov    0x8(%esp),%eax
      0x89, 0xcc,                               //  mov    %ecx,%esp
      0xff, 0xe2,                               //  jmp    *%edx
    };

    LjPatterns.emplace_back(
        llvm::StringRef(reinterpret_cast<const char *>(&pattern[0]),
                        sizeof(pattern)),
        0);
  }

  {
    // glibc
    static const uint8_t pattern[] = {
      0x8b, 0x44, 0x24, 0x04,                   // mov    0x4(%esp),%eax
      0x89, 0x18,                               // mov    %ebx,(%eax)
      0x89, 0x70, 0x04,                         // mov    %esi,0x4(%eax)
      0x89, 0x78, 0x08,                         // mov    %edi,0x8(%eax)
      0x8d, 0x4c, 0x24, 0x04,                   // lea    0x4(%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x48, 0x10,                         // mov    %ecx,0x10(%eax)
      0x8b, 0x0c, 0x24,                         // mov    (%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x48, 0x14,                         // mov    %ecx,0x14(%eax)
      0x89, 0x68, 0x0c,                         // mov    %ebp,0xc(%eax)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // glibc
    static const uint8_t pattern[] = {
      0x31, 0xc0,                               // xor    %eax,%eax
      0x8b, 0x54, 0x24, 0x04,                   // mov    0x4(%esp),%edx
      0x89, 0x1a,                               // mov    %ebx,(%edx)
      0x89, 0x72, 0x04,                         // mov    %esi,0x4(%edx)
      0x89, 0x7a, 0x08,                         // mov    %edi,0x8(%edx)
      0x8d, 0x4c, 0x24, 0x04,                   // lea    0x4(%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x4a, 0x10,                         // mov    %ecx,0x10(%edx)
      0x8b, 0x0c, 0x24,                         // mov    (%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x4a, 0x14,                         // mov    %ecx,0x14(%edx)
      0x89, 0x6a, 0x0c,                         // mov    %ebp,0xc(%edx)
      0x89, 0x42, 0x18,                         // mov    %eax,0x18(%edx)
      0xc3                                      // ret
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // haloce.exe
    static const uint8_t pattern[] = {
      0x8b, 0x54, 0x24, 0x04,                   // mov    0x4(%esp),%edx
      0x89, 0x2a,                               // mov    %ebp,(%edx)
      0x89, 0x5a, 0x04,                         // mov    %ebx,0x4(%edx)
      0x89, 0x7a, 0x08,                         // mov    %edi,0x8(%edx)
      0x89, 0x72, 0x0c,                         // mov    %esi,0xc(%edx)
      0x89, 0x62, 0x10,                         // mov    %esp,0x10(%edx)
      0x8b, 0x04, 0x24,                         // mov    (%esp),%eax
      0x89, 0x42, 0x14,                         // mov    %eax,0x14(%edx)
      0xc7, 0x42, 0x20, 0x30, 0x32, 0x43, 0x56, // movl   $0x56433230,0x20(%edx)
      0xc7, 0x42, 0x24, 0x00, 0x00, 0x00, 0x00, // movl   $0x0,0x24(%edx)
      0x64, 0xa1, 0x00, 0x00, 0x00, 0x00,       // mov    %fs:0x0,%eax
      0x89, 0x42, 0x18,                         // mov    %eax,0x18(%edx)
      0x83, 0xf8, 0xff,                         // cmp    $0xffffffff,%eax
      0x75, 0x09,                               // jne    0x5ccef9
      0xc7, 0x42, 0x1c, 0xff, 0xff, 0xff, 0xff, // movl   $0xffffffff,0x1c(%edx)
      0xeb, 0x3b,                               // jmp    0x5ccf34
      0x8b, 0x4c, 0x24, 0x08,                   // mov    0x8(%esp),%ecx
      0x0b, 0xc9,                               // or     %ecx,%ecx
      0x74, 0x0a,                               // je     0x5ccf0b
      0x8b, 0x44, 0x24, 0x0c,                   // mov    0xc(%esp),%eax
      0x89, 0x42, 0x24,                         // mov    %eax,0x24(%edx)
      0x49,                                     // dec    %ecx
      0x75, 0x08,                               // jne    0x5ccf13
      0x8b, 0x40, 0x0c,                         // mov    0xc(%eax),%eax
      0x89, 0x42, 0x1c,                         // mov    %eax,0x1c(%edx)
      0xeb, 0x21,                               // jmp    0x5ccf34
      0x8b, 0x44, 0x24, 0x10,                   // mov    0x10(%esp),%eax
      0x89, 0x42, 0x1c,                         // mov    %eax,0x1c(%edx)
      0x49,                                     // dec    %ecx
      0x74, 0x17,                               // je     0x5ccf34
      0x56,                                     // push   %esi
      0x57,                                     // push   %edi
      0x8d, 0x74, 0x24, 0x1c,                   // lea    0x1c(%esp),%esi
      0x8d, 0x7a, 0x28,                         // lea    0x28(%edx),%edi
      0x83, 0xf9, 0x06,                         // cmp    $0x6,%ecx
      0x76, 0x05,                               // jbe    0x5ccf30
      0xb9, 0x06, 0x00, 0x00, 0x00,             // mov    $0x6,%ecx
      0xf3, 0xa5,                               // rep movsl %ds:(%esi),%es:(%edi)
      0x5f,                                     // pop    %edi
      0x5e,                                     // pop    %esi
      0x2b, 0xc0,                               // sub    %eax,%eax
      0xc3                                      // ret
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // haloce.exe
    static const uint8_t pattern[] = {
      0x8b, 0x5c, 0x24, 0x04,                   // mov    0x4(%esp),%ebx
      0x8b, 0x2b,                               // mov    (%ebx),%ebp
      0x8b, 0x73, 0x18,                         // mov    0x18(%ebx),%esi
      0x64, 0x3b, 0x35, 0x00, 0x00, 0x00, 0x00, // cmp    %fs:0x0,%esi
      0x74, 0x09,                               // je     0x5cce5b
      0x56,                                     // push   %esi
      0xe8, 0x40, 0x08, 0x00, 0x00,             // call   0x5cd698
      0x83, 0xc4, 0x04,                         // add    $0x4,%esp
      0x83, 0xfe, 0x00,                         // cmp    $0x0,%esi
      0x74, 0x30,                               // je     0x5cce90
      0x8d, 0x43, 0x20,                         // lea    0x20(%ebx),%eax
      0x50,                                     // push   %eax
      0xe8, 0xb3, 0xa5, 0x00, 0x00,             // call   0x5d741c
      0x0b, 0xc0,                               // or     %eax,%eax
      0x74, 0x16,                               // je     0x5cce83
      0x8b, 0x43, 0x20,                         // mov    0x20(%ebx),%eax
      0x3d, 0x30, 0x32, 0x43, 0x56,             // cmp    $0x56433230,%eax
      0x75, 0x0c,                               // jne    0x5cce83
      0x8b, 0x43, 0x24,                         // mov    0x24(%ebx),%eax
      0x0b, 0xc0,                               // or     %eax,%eax
      0x74, 0x12,                               // je     0x5cce90
      0x53,                                     // push   %ebx
      0xff, 0xd0,                               // call   *%eax
      0xeb, 0x0d,                               // jmp    0x5cce90
      0x8b, 0x43, 0x1c,                         // mov    0x1c(%ebx),%eax
      0x50,                                     // push   %eax
      0x56,                                     // push   %esi
      0xe8, 0x4d, 0x08, 0x00, 0x00,             // call   0x5cd6da
      0x83, 0xc4, 0x08,                         // add    $0x8,%esp
      0x6a, 0x00,                               // push   $0x0
      0x8b, 0x43, 0x14,                         // mov    0x14(%ebx),%eax
      0xe8, 0xd4, 0x08, 0x00, 0x00,             // call   0x5cd76e
      0x8b, 0xd3,                               // mov    %ebx,%edx
      0x8b, 0x5a, 0x04,                         // mov    0x4(%edx),%ebx
      0x8b, 0x7a, 0x08,                         // mov    0x8(%edx),%edi
      0x8b, 0x72, 0x0c,                         // mov    0xc(%edx),%esi
      0x8b, 0x44, 0x24, 0x08,                   // mov    0x8(%esp),%eax
      0x83, 0xf8, 0x01,                         // cmp    $0x1,%eax
      0x83, 0xd0, 0x00,                         // adc    $0x0,%eax
      0x8b, 0x62, 0x10,                         // mov    0x10(%edx),%esp
      0x83, 0xc4, 0x04,                         // add    $0x4,%esp
      0xff, 0x62, 0x14,                         // jmp    *0x14(%edx)
    };

    LjPatterns.emplace_back(
        llvm::StringRef(reinterpret_cast<const char *>(&pattern[0]),
                        sizeof(pattern)),
        sizeof(pattern) - 3);
  }

#elif defined(TARGET_MIPS32)
  {
    // glibc
    static const uint32_t pattern[] = {
      0xd4940038,                               // ldc1    $f20,56(a0)
      0xd4960040,                               // ldc1    $f22,64(a0)
      0xd4980048,                               // ldc1    $f24,72(a0)
      0xd49a0050,                               // ldc1    $f26,80(a0)
      0xd49c0058,                               // ldc1    $f28,88(a0)
      0xd49e0060,                               // ldc1    $f30,96(a0)
      0x8c9c002c,                               // lw      gp,44(a0)
      0x8c900008,                               // lw      s0,8(a0)
      0x8c91000c,                               // lw      s1,12(a0)
      0x8c920010,                               // lw      s2,16(a0)
      0x8c930014,                               // lw      s3,20(a0)
      0x8c940018,                               // lw      s4,24(a0)
      0x8c95001c,                               // lw      s5,28(a0)
      0x8c960020,                               // lw      s6,32(a0)
      0x8c970024,                               // lw      s7,36(a0)
      0x8c990000,                               // lw      t9,0(a0)
      0x8c9d0004,                               // lw      sp,4(a0)
      0x14a00005,                               // bnez    a1,354ec
      0x8c9e0028,                               // lw      s8,40(a0)
      0x03200008,                               // jr      t9
      0x24020001,                               // li      v0,1
      0x1000ffff,                               // b       354e4
      0x00000000,                               // nop
      0x03200008,                               // jr      t9
      0x00a01025,                               // move    v0,a1
    };

    LjPatterns.emplace_back(
        llvm::StringRef(reinterpret_cast<const char *>(&pattern[0]),
                        sizeof(pattern)),
        sizeof(pattern) - 2 * 4);

    LjPatterns.emplace_back(
        llvm::StringRef(reinterpret_cast<const char *>(&pattern[0]),
                        sizeof(pattern)),
        sizeof(pattern) - 6 * 4);
  }

  {
    // libuClibc
    static const uint32_t pattern[] = {
      0xc4940038,                               // lwc1    $f20,56(a0)
      0xc495003c,                               // lwc1    $f21,60(a0)
      0xc4960040,                               // lwc1    $f22,64(a0)
      0xc4970044,                               // lwc1    $f23,68(a0)
      0xc4980048,                               // lwc1    $f24,72(a0)
      0xc499004c,                               // lwc1    $f25,76(a0)
      0xc49a0050,                               // lwc1    $f26,80(a0)
      0xc49b0054,                               // lwc1    $f27,84(a0)
      0xc49c0058,                               // lwc1    $f28,88(a0)
      0xc49d005c,                               // lwc1    $f29,92(a0)
      0xc49e0060,                               // lwc1    $f30,96(a0)
      0xc49f0064,                               // lwc1    $f31,100(a0)
      0x8c820030,                               // lw      v0,48(a0)
      0x00000000,                               // nop
      0x44c2f800,                               // ctc1    v0,c1_fcsr
      0x8c9c002c,                               // lw      gp,44(a0)
      0x8c900008,                               // lw      s0,8(a0)
      0x8c91000c,                               // lw      s1,12(a0)
      0x8c920010,                               // lw      s2,16(a0)
      0x8c930014,                               // lw      s3,20(a0)
      0x8c940018,                               // lw      s4,24(a0)
      0x8c95001c,                               // lw      s5,28(a0)
      0x8c960020,                               // lw      s6,32(a0)
      0x8c970024,                               // lw      s7,36(a0)
      0x8c990000,                               // lw      t9,0(a0)
      0x8c9d0004,                               // lw      sp,4(a0)
      0x8c9e0028,                               // lw      s8,40(a0)
      0x14a00003,                               // bnez    a1,4cbfc
      0x00000000,                               // nop
      0x10000002,                               // b       4cc00
      0x24020001,                               // li      v0,1
      0x00a01021,                               // move    v0,a1
      0x03200008,                               // jr      t9
      0x00000000,                               // nop
    };

    LjPatterns.emplace_back(
        llvm::StringRef(reinterpret_cast<const char *>(&pattern[0]),
                        sizeof(pattern)),
        sizeof(pattern) - 2 * 4);
  }
  {
    // glibc
    static const uint32_t pattern[] = {
      0xf4940038,                               // sdc1    $f20,56(a0)
      0xf4960040,                               // sdc1    $f22,64(a0)
      0xf4980048,                               // sdc1    $f24,72(a0)
      0xf49a0050,                               // sdc1    $f26,80(a0)
      0xf49c0058,                               // sdc1    $f28,88(a0)
      0xf49e0060,                               // sdc1    $f30,96(a0)
      0xac9f0000,                               // sw      ra,0(a0)
      0xac860004,                               // sw      a2,4(a0)
      0xac870028,                               // sw      a3,40(a0)
      0xac9c002c,                               // sw      gp,44(a0)
      0xac900008,                               // sw      s0,8(a0)
      0xac91000c,                               // sw      s1,12(a0)
      0xac920010,                               // sw      s2,16(a0)
      0xac930014,                               // sw      s3,20(a0)
      0xac940018,                               // sw      s4,24(a0)
      0xac95001c,                               // sw      s5,28(a0)
      0xac960020,                               // sw      s6,32(a0)
      0xac970024,                               // sw      s7,36(a0)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
  {
    // libuClibc
    static const uint32_t pattern[] = {
      0x00801021,                               // move    v0,a0
      0xe4940038,                               // swc1    $f20,56(a0)
      0xe495003c,                               // swc1    $f21,60(a0)
      0xe4960040,                               // swc1    $f22,64(a0)
      0xe4970044,                               // swc1    $f23,68(a0)
      0xe4980048,                               // swc1    $f24,72(a0)
      0xe499004c,                               // swc1    $f25,76(a0)
      0xe49a0050,                               // swc1    $f26,80(a0)
      0xe49b0054,                               // swc1    $f27,84(a0)
      0xe49c0058,                               // swc1    $f28,88(a0)
      0xe49d005c,                               // swc1    $f29,92(a0)
      0xe49e0060,                               // swc1    $f30,96(a0)
      0xe49f0064,                               // swc1    $f31,100(a0)
      0xac9f0000,                               // sw      ra,0(a0)
      0xac860004,                               // sw      a2,4(a0)
      0xac870028,                               // sw      a3,40(a0)
      0xac9c002c,                               // sw      gp,44(a0)
      0xac900008,                               // sw      s0,8(a0)
      0xac91000c,                               // sw      s1,12(a0)
      0xac920010,                               // sw      s2,16(a0)
      0xac930014,                               // sw      s3,20(a0)
      0xac940018,                               // sw      s4,24(a0)
      0xac95001c,                               // sw      s5,28(a0)
      0xac960020,                               // sw      s6,32(a0)
      0xac970024,                               // sw      s7,36(a0)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
#elif defined(TARGET_MIPS64)
  {
    // glibc
    static const uint32_t pattern[] = {
      0xf4980068,                               // sdc1    $f24,104(a0)
      0xf4990070,                               // sdc1    $f25,112(a0)
      0xf49a0078,                               // sdc1    $f26,120(a0)
      0xf49b0080,                               // sdc1    $f27,128(a0)
      0xf49c0088,                               // sdc1    $f28,136(a0)
      0xf49d0090,                               // sdc1    $f29,144(a0)
      0xf49e0098,                               // sdc1    $f30,152(a0)
      0xf49f00a0,                               // sdc1    $f31,160(a0)
      0xfc9f0000,                               // sd      ra,0(a0)
      0xfc860008,                               // sd      a2,8(a0)
      0xfc870050,                               // sd      a3,80(a0)
      0xfc880058,                               // sd      a4,88(a0)
      0xfc900010,                               // sd      s0,16(a0)
      0xfc910018,                               // sd      s1,24(a0)
      0xfc920020,                               // sd      s2,32(a0)
      0xfc930028,                               // sd      s3,40(a0)
      0xfc940030,                               // sd      s4,48(a0)
      0xfc950038,                               // sd      s5,56(a0)
      0xfc960040,                               // sd      s6,64(a0)
      0xfc970048,                               // sd      s7,72(a0)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
#elif defined(TARGET_AARCH64)
  {
    // glibc
    static const uint32_t pattern[] = {
      0xa9005013,    // stp     x19, x20, [x0]
      0xa9015815,    // stp     x21, x22, [x0, #16]
      0xa9026017,    // stp     x23, x24, [x0, #32]
      0xa9036819,    // stp     x25, x26, [x0, #48]
      0xa904701b,    // stp     x27, x28, [x0, #64]

/*
      0xb0000b22     // adrp    x2, 19f000 <sys_sigabbrev@GLIBC_2.17+0x1c0>
      0xf9471842     // ldr     x2, [x2, #3632]
      0xf9400043     // ldr     x3, [x2]
      0xca0303c4     // eor     x4, x30, x3
      0xa905101d     // stp     x29, x4, [x0, #80]
      0x6d072408     // stp     d8, d9, [x0, #112]
      0x6d082c0a     // stp     d10, d11, [x0, #128]
      0x6d09340c     // stp     d12, d13, [x0, #144]
      0x6d0a3c0e     // stp     d14, d15, [x0, #160]
*/

    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
#endif

  std::string PrintStr;
  llvm::raw_string_ostream OS(PrintStr);

  auto found_setjmp = [&](uint64_t A) -> void {
    if (E.IsVerbose())
      OS << llvm::formatv("found setjmp @ {0}:{1:x}\n", b.Name.c_str(), A);

    basic_block_index_t BBIdx = E.explore_basic_block(b, Bin, A);
    assert(is_basic_block_index_valid(BBIdx));

    auto &ICFG = b.Analysis.ICFG;
    ICFG[basic_block_of_index(BBIdx, ICFG)].Sj = true;
  };

  auto found_longjmp = [&](uint64_t A) -> void {
    if (E.IsVerbose())
      OS << llvm::formatv("found longjmp @ {0}:{1:x}\n", b.Name.c_str(), A);

    basic_block_index_t BBIdx = E.explore_basic_block(b, Bin, A);
    assert(is_basic_block_index_valid(BBIdx));

    auto &ICFG = b.Analysis.ICFG;
    auto bb = basic_block_of_index(BBIdx, ICFG);

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

    if (ICFG.out_degree(bb) != 0) {
      if (E.IsVerbose())
        OS << llvm::formatv("jump aint local! @ {0:x}\n", ICFG[bb].Addr);
      ICFG.clear_out_edges(bb);
    }

    ICFG[bb].Term._indirect_jump.IsLj = true;
  };


  if (E.IsVeryVerbose())
    OS << llvm::formatv("sjlj: {0}\n", b.Name.c_str());

  B::_elf(Bin, [&](ELFO &O) {
  const ELFF &Elf = O.getELFFile();
  auto ProgramHeadersOrError = Elf.program_headers();
  if (ProgramHeadersOrError) {
    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

    for (const Elf_Phdr &Phdr : *ProgramHeadersOrError)
      if (Phdr.p_type == llvm::ELF::PT_LOAD)
        LoadSegments.push_back(const_cast<Elf_Phdr *>(&Phdr));

    for (const Elf_Phdr *P : LoadSegments) {
      llvm::StringRef SectionStr(
          reinterpret_cast<const char *>(Elf.base() + P->p_offset), P->p_filesz);

      if (E.IsVeryVerbose())
        OS << llvm::formatv("  PT_LOAD [0x{0:x},0x{1:x})\t{2}\n", P->p_vaddr,
                            P->p_vaddr + P->p_memsz, b.Name.c_str());

      for (const auto &pair : LjPatterns) {
        llvm::StringRef pattern = pair.first;

        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        int off = pair.second;
        found_longjmp(P->p_vaddr + idx + off);
      }

      for (llvm::StringRef pattern : SjPatterns) {
        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        found_setjmp(P->p_vaddr + idx);
      }
    }
  }
  });

  B::_coff(Bin, [&](COFFO &O) {
    for (const obj::SectionRef &S : O.sections()) {
      const obj::coff_section *Section = O.getCOFFSection(S);
      if (!(Section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE))
        continue;

      llvm::StringRef SectionStr(
          &Bin.getMemoryBufferRef().getBufferStart()[Section->PointerToRawData],
          Section->SizeOfRawData);

      for (const auto &pair : LjPatterns) {
        llvm::StringRef pattern = pair.first;

        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        int off = pair.second;
        found_longjmp(coff::va_of_rva(O, Section->VirtualAddress + idx + off));
      }

      for (llvm::StringRef pattern : SjPatterns) {
        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        found_setjmp(coff::va_of_rva(O, Section->VirtualAddress + idx));
      }
    }
  });

  {
    static std::mutex mtx;
    std::unique_lock<std::mutex> lk(mtx);

    llvm::errs() << PrintStr;
  }
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template void ScanForSjLj(                                                   \
      binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                  \
                    GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &,               \
      llvm::object::Binary &,                                                  \
      explorer_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                     \
                 GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &);

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
