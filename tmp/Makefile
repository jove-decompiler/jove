all: x86_64.tcg.o

%.o: %.cpp
	clang++ -c -o $@ -Wall -Wno-macro-redefined -std=gnu++14 -I qemu/tcg -I qemu/include -I qemu -I qemu/target/i386 -I qemu/accel/tcg -DNEED_CPU_H  $<
