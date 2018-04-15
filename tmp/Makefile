CFLAGS := -Wall -Wno-macro-redefined -fPIC -flto -I qemu/tcg -I qemu/include -I qemu -I qemu/target/i386 -I qemu/accel/tcg -DNEED_CPU_H
CXXFLAGS := -std=gnu++14

x86_64-tcg: x86_64_tcg.o
	clang++ -o $@ $(CFLAGS) $< -lglib-2.0

%.o: %.cpp
	clang++ -o $@ -c $(CFLAGS) $(CXXFLAGS) $<

.PHONY: clean
clean:
	rm -f *.o *.so x86_64-tcg
