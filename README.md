[![CI](https://github.com/jove-decompiler/jove/actions/workflows/CI.yml/badge.svg)](https://github.com/jove-decompiler/jove/actions/workflows/CI.yml)

![](.araki.png)

# JOVE README
`jove` is a decompiler for C programs built on top of [QEMU User-mode emulation](https://www.qemu.org/), [LLVM](https://llvm.org/docs/LangRef.html), and [`llvm-cbe`](https://github.com/JuliaHubOSS/llvm-cbe). By observing control-flow at runtime, it is capable of perfectly disassembling machine-code binaries. The output is such that it can be modified, recompiled, and, executed. It targets userland linux on `i386`/`x86_64`/`mips`/`mipsel`/`mips64el`/`aarch64`, and Windows executables under WINE on `x86`/`x64`.

```
jove [tool [arguments]...]
```
#### Currently defined tools:
`check-helper` `dump-vdso` `add` `addr2off` `analyze` `block` `bootstrap` `callstack` `cfg` `decompile` `dig` `dump` `extract` `function` `ida` `init` `invalidate` `ipt` `llvm` `loop` `numbers` `off2addr` `readtrace` `recompile` `recover` `run` `sanity` `scan` `score` `serialize` `server` `stub` `trace` `trace2addrs` `trace2asm` `trace2lines` `unlock` `unserialize` `unstub` `jv2xml` `llknife` `tcgdump`

## USAGE
```bash
$ alias jove='jove-x86_64'
$ jove init /usr/bin/ls               # initialize .jv
$ jove bootstrap /usr/bin/ls -la /    # recover code executed by command (this step can be skipped)
$ jove loop /usr/bin/ls -la /         # re-run command through recompilation
$ jove decompile -o ls.src            # generate C code source tree
$ make -C ls.src                      # make executable from decompilation
```

For a quickstart, use the [docker image](https://hub.docker.com/repository/docker/aleden22/jove/general) and see [Examples.md](/Documentation/Examples.md).

## FAQ

### How is control-flow observed at runtime?
1. `jove bootstrap` is a custom `ptrace(2)`-based tracer, which overwrites every known block terminator instruction with a software breakpoint. Luckily, terminator instructions are essentially trivial to emulate[^2] in-place[^5]. At the moment it only supports linux, but it is totally feasible to eventually add support for Windows executables under WINE.
2. `jove ipt` is a custom `Intel Processor Trace`-based tracer[^3]. Crucially, unlike `jove bootstrap`, its overhead is extremely low, which makes it suitable for serious interactive applications (e.g. games). It is supported on all platforms. Unfortunately, there is commonly troublesome "errata" for older processors.

### What about static control-flow recovery?
Whenever it is sound to do so, `jove` will statically recover code. After all, the goal is to recover as much code as possible.

The classic abstract interpretation for which there are open-source implementations widely available (e.g. [BAP](https://github.com/BinaryAnalysisPlatform/bap)) is Value Set Analysis (VSA). Basically it's just reasoning about strided intervals. Eventually `jove` may acquire an implementation of VSA.

**However:** `jove` contains a novel solution for this problem that is _far_ more general: `jove dig` (also known as `CodeDigger`), a fork of [KLEE](https://github.com/jove-decompiler/klee). The idea[^6] is to perform "local" symbolic execution: starting from the program point which jumps into who-knows-what (as opposed to starting from the beginning of the program which leads to an explosion of paths for any serious program), looking backwards we obtain _partial_ program paths. `jove dig` executes these partial paths and [interrogates the solver for a complete set of targets](https://github.com/jove-decompiler/klee/blob/9bede692834bef4ac265b3cb2a3df35e3dd06e78/lib/Core/Executor.cpp#L2265). If the program counter expression is sufficiently constrained, the solver will be able to do so. Obviously there will be still indirect jumps for which we can say practically nothing about[^1]. The drawback of this tool, at the moment, is that it requires considerable time and space.

`jove ida` allows one to import control-flow data from [IDA](https://hex-rays.com/ida-pro). However this is not advisable: since IDA is closed-source, we really don't know what it's actually doing under the covers.

`jove ida` is very rudimentary. That may change if someone decides to generously donate an IDA license. [^4]

### Doesn't `llvm-cbe` contain flaws?
We only demand `llvm-cbe` handle a tiny subset of the [gigantic LLVM language specification](https://llvm.org/docs/LangRef.html). This proper subset is produced by `jove llvm`, which translates the straightforward [TCG](https://github.com/qemu/qemu/blob/master/docs/devel/tcg-ops.rst) (QEMU's intermediate language) instructions into LLVM instructions and is (much of the time) essentially a one-to-one mapping.

The C code `jove decompile` produces for non-trivial machine code instructions does **not** involve `llvm-cbe`. [It originates from QEMU's sources practically verbatim, by using `clang` to compile QEMU with a custom plugin](https://github.com/aleden/carbon-copy). Luckily, QEMU is nearly completely written in C, and compiles under `clang`.

### How on earth is `jove` tested?
The CI test suite [spins up](https://github.com/jove-decompiler/mk-deb-vm) whole-system debian linux emulations (via `qemu-system-*`) for all the architectures. Thus we can test `jove` with ease on all the architectures, without needing the elusive physical machines to do so.

The [latest docker image](https://hub.docker.com/repository/docker/aleden22/jove/general) is guaranteed to have passed the aforementioned test suite.

[^1]: In theory, VSA would do no better.
[^2]: 32-bit `arm` is a known exception, but we don't currently support this architecture.
[^3]: This processor feature is only available on Intel x86 CPUs.
[^4]: IDA licenses cost an obscene quantity of money.
[^5]: The Linux kernel implements UProbe tracepoints in a more general way by copying the instruction (which was replaced by a trap) to a dedicated memory region, possibly patching it (to handle any references to the current value of the instruction pointer)- and executing it _there_.
[^6]: Credit for this idea [goes to Tim Leek](https://www.ll.mit.edu/biographies/tim-leek).
