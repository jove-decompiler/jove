all: x86_64.tcg.so

%.so: %.o
	clang++ -o $@ -shared -fuse-ld=lld -Xlinker --no-undefined -Xlinker -error-limit=0 $< -lglib-2.0

%.o: %.cpp
	clang++ -o $@ -c -fPIC -Wall -Wno-macro-redefined -std=gnu++14 -I qemu/tcg -I qemu/include -I qemu -I qemu/target/i386 -I qemu/accel/tcg -DNEED_CPU_H $<

.PHONY: clean
clean:
	rm -f *.o *.so
