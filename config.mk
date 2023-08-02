ALL_TARGETS := i386 x86_64 aarch64 mipsel mips mips64el

aarch64_sysroot  := /usr/aarch64-linux-gnu
x86_64_sysroot   := /
i386_sysroot     := /usr/i686-linux-gnu
mipsel_sysroot   := /usr/mipsel-linux-gnu
mips_sysroot     := /usr/mips-linux-gnu
mips64el_sysroot := /usr/mips64el-linux-gnuabi64

aarch64_TRIPLE  := aarch64-linux-gnu
i386_TRIPLE     := i686-linux-gnu
x86_64_TRIPLE   := x86_64-linux-gnu
mipsel_TRIPLE   := mipsel-linux-gnu
mips_TRIPLE     := mips-linux-gnu
mips64el_TRIPLE := mips64el-linux-gnuabi64
