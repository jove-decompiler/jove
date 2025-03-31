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
$ jove decompile -o ls.src            # generate decompilation source tree
$ make -C ls.src                      # make executable from decompilation
```

For a quickstart, use the [docker image](https://hub.docker.com/repository/docker/aleden22/jove/general) and see [Examples.md](/Documentation/Examples.md).
