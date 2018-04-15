CFLAGS := -Wall -Wno-macro-redefined -fPIC -flto -I qemu/tcg -I qemu/include -I qemu -I qemu/target/i386 -I qemu/accel/tcg -DNEED_CPU_H
CXXFLAGS += -std=gnu++14 -fno-rtti -fno-exceptions
LDFLAGS += $(shell pkg-config --libs glib-2.0)
LDFLAGS += $(shell llvm-config --ldflags --libs)
LDFLAGS += -lboost_filesystem -lboost_system

x86_64-tcg: x86_64_tcg.o
	clang++ -o $@ $(CFLAGS) $< $(LDFLAGS)

%.o: %.cpp
	clang++ -o $@ -c $(CFLAGS) $(CXXFLAGS) $<

.PHONY: clean
clean:
	rm -f *.o *.so x86_64-tcg
