ALL_TARGETS := i386 x86_64 aarch64 mipsel mips64el

aarch64_TRIPLE  := aarch64-linux-gnu
i386_TRIPLE     := i686-linux-gnu
x86_64_TRIPLE   := x86_64-linux-gnu
mipsel_TRIPLE   := mipsel-linux-gnu
mips_TRIPLE     := mips-linux-gnu
mips64el_TRIPLE := mips64el-linux-gnuabi64

aarch64_LD_EMU  := aarch64linux
x86_64_LD_EMU   := elf_x86_64
i386_LD_EMU     := elf_i386
mipsel_LD_EMU   := elf32ltsmip
mips_LD_EMU     := elf32btsmip
mips64el_LD_EMU := elf64ltsmip

i386_COFF_TRIPLE   := i386-windows-gnu
x86_64_COFF_TRIPLE := x86_64-windows-gnu

i386_COFF_LD_EMU   := i386pe
x86_64_COFF_LD_EMU := i386pep

i386_COFF_MACHINE   := x86
x86_64_COFF_MACHINE := x64
