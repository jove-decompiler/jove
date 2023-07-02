FROM docker.io/library/debian:12-slim

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
                      llvm-15 \
                      locales \
                      make \
                      meson \
                      ninja-build \
                      openssh-client \
                      pkg-config \
                      pkgconf \
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
                      zlib1g-dev:arm64 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y
