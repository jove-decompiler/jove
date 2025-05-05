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

### How do you observe control-flow at runtime?
There are currently two ways:
1. `jove bootstrap` is a custom `ptrace(2)`-based tracer which places software breakpoints at the address of every known block terminator. Luckily, terminator instructions are essentially trivial to emulate (`armhf` is an exception, but we don't currently support this architecture). At the moment it only supports linux, but adding support for Windows executables is quite a feasible task.
2. `jove ipt` is a custom `Intel Processor Trace`-based tracer (this is only available on x86 Intel CPUs) to recover code. Crucially it's overhead is extremely low, which makes it suitable for real-time applications (e.g. games).

### What about statically recovering control-flow?
Whenever it is sound to do so, `jove` will statically recover code.

The classic off-the-shelf abstract interpretation that is widely used, and for which there are open-source implementations widely available (e.g. BAP), is Value Set Analysis (VSA). `jove` will, probably, eventually acquire this feature.

However, `jove` contains something far more general: namely the `dig` tool (A.K.A. `CodeDigger`). This tool uses a novel approach to control-flow-recovery, and the idea (credit goes to Tim Leek) is to perform local symbolic execution from each program point which has indirect control-flow, and then ask the solver to try and come up with a complete set of feasible values. If there are sufficient constraints, the solver will be able to do so. Obviously, there will still be indirect jumps for which we can say very little (or practically nothing) about[^1]. `CodeDigger` is implemented as a custom fork of `KLEE`.

The drawback, at the moment, is that it has considerable time and space requirements.

[^1]: In theory, VSA would do no better.

### But isn't `llvm-cbe` not "perfect"?
We only demand `llvm-cbe` to handle a tiny subset of the LLVM language. All of it is produced by `jove llvm`, which translates the TCG (the QEMU intermediate code) into simple LLVM instructions. Whenever we encounter non-trivial machine code instructions, the C code [comes directly from comes](https://github.com/aleden/carbon-copy) QEMU, which are luckily implemented in C.
