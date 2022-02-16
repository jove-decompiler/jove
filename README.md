# Download
https://images.aarno-labs.com/jove/

These programs are statically-linked and portable; they can be placed anywhere in the filesystem.

## Installation
```bash
mkdir /opt/jove
tar -xvf jove.v0.79b-x86_64.tar.xz -C /opt/jove
```

## Usage
Choose one of the target architectures (i386, x86_64, mips, mipsel, mips64, aarch64) and add the relevant directory to your $PATH. For example:

```bash
export PATH=$PATH:/opt/jove/x86_64
```

`jove-bootstrap` requires that the target architecture matches the host's.

# FAQ
### What is jove?
A: Given a dynamically linked linux executable `E` and a set of inputs `I`, jove produces source code for `E` that, when compiled and run, produces the same results for `I` as the original program.
