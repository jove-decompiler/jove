FROM docker.io/library/debian:12-slim AS builder

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y eatmydata && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
                      autoconf \
                      automake \
                      bash \
                      binutils-dev \
                      ca-certificates \
                      clang-15 \
                      cmake \
                      g++-aarch64-linux-gnu \
                      g++-multilib-i686-linux-gnu \
                      g++-multilib-mips-linux-gnu \
                      g++-multilib-mips64el-linux-gnuabi64 \
                      g++-multilib-mipsel-linux-gnu \
                      gcc \
                      git \
                      gmsl \
                      graphviz \
                      hostname \
                      libboost-all-dev \
                      libglib2.0-dev \
                      libgraph-easy-perl \
                      libpcre2-dev \
                      libtinfo-dev \
                      libtool \
                      libxml2-dev \
                      libz3-dev \
                      lld-15 \
                      llvm-15 \
                      locales \
                      make \
                      meson \
                      ninja-build \
                      openssh-client \
                      parted \
                      pkg-config \
                      pkgconf \
                      python3-venv \
                      sed \
                      sudo \
                      unzip \
                      vim-common \
                      tar && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture i386 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:i386 \
                      libglib2.0-dev:i386 \
                      libboost-system-dev:i386 \
                      libboost-filesystem-dev:i386 \
                      libboost-serialization-dev:i386 \
                      zlib1g-dev:i386 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mipsel && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:mipsel \
                      libglib2.0-dev:mipsel \
                      libboost-system-dev:mipsel \
                      libboost-filesystem-dev:mipsel \
                      libboost-serialization-dev:mipsel \
                      zlib1g-dev:mipsel && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mips64el && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:mips64el \
                      libglib2.0-dev:mips64el \
                      libboost-system-dev:mips64el \
                      libboost-filesystem-dev:mips64el \
                      libboost-serialization-dev:mips64el \
                      zlib1g-dev:mips64el && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture arm64 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:arm64 \
                      libglib2.0-dev:arm64 \
                      libboost-system-dev:arm64 \
                      libboost-filesystem-dev:arm64 \
                      libboost-serialization-dev:arm64 \
                      zlib1g-dev:arm64 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

ADD . /jove/
RUN /jove/scripts/build/build.sh

FROM docker.io/library/debian:12-slim

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y eatmydata && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
                      libffi-dev \
                      libboost-system-dev \
                      libboost-filesystem-dev \
                      libboost-serialization-dev \
                      libglib2.0-dev \
                      libatomic1 \
                      libstdc++6 \
                      libtinfo-dev \
                      libpcre2-dev \
                      zlib1g-dev && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales

COPY --from=builder /jove/{scripts,prebuilts} /opt/jove/
COPY --from=builder /jove/llvm-project/build/bin/jove-* /opt/jove/bin/
COPY --from=builder /jove/llvm-project/build/bin/llc /opt/jove/bin/
COPY --from=builder /jove/llvm-project/build/bin/opt /opt/jove/bin/
COPY --from=builder /jove/llvm-project/build/bin/llvm-dis /opt/jove/bin/
COPY --from=builder /jove/llvm-project/build/bin/ld* /opt/jove/bin/
COPY --from=builder /jove/llvm-project/build/bin/lld /opt/jove/bin/
COPY --from=builder /jove/llvm-project/build/bin/llvm-readobj /opt/jove/bin/
COPY --from=builder /jove/llvm-project/i386_build/bin/jove-i386 /opt/jove/bin/cross/
COPY --from=builder /jove/llvm-project/mipsel_build/bin/jove-mipsel /opt/jove/bin/cross/
COPY --from=builder /jove/llvm-project/mips64el_build/bin/jove-mips64el /opt/jove/bin/cross/
COPY --from=builder /jove/llvm-project/aarch64_build/bin/jove-aarch64 /opt/jove/bin/cross/
