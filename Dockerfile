FROM docker.io/library/debian:12-slim AS builder

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y eatmydata && \
    dpkg --add-architecture i386 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
                      gettext:i386 \
                      gstreamer1.0-dev:i386 \
                      gstreamer1.0-plugins-base:i386 \
                      gstreamer1.0-plugins-good:i386 \
                      libasound2-plugins:i386 \
                      libavcodec-dev:i386 \
                      libavdevice-dev:i386 \
                      libbabeltrace1:i386 \
                      libc6-dev:i386 \
                      libcapi20-dev:i386 \
                      libcups2-dev:i386 \
                      libcurl3-gnutls:i386 \
                      libcurl4:i386 \
                      libdebuginfod-dev:i386 \
                      libegl1-mesa-dev:i386 \
                      libfontconfig-dev:i386 \
                      libfontconfig-dev:i386 \
                      libfreetype-dev:i386 \
                      libgav1-dev:i386 \
                      libgd3:i386 \
                      libgdm-dev:i386 \
                      libglib2.0-dev:i386 \
                      libgnutls28-dev:i386 \
                      libgstreamer-plugins-base1.0-dev:i386 \
                      libgstreamer1.0-dev:i386 \
                      libltdl-dev:i386 \
                      libmpfr-dev:i386 \
                      libodbc2:i386 \
                      libosmesa6-dev:i386 \
                      libpcap-dev:i386 \
                      libpython3-dev:i386 \
                      libreadline8:i386 \
                      libsdl2-dev:i386 \
                      libssh2-1:i386 \
                      libsystemd-dev:i386 \
                      liburing-dev:i386 \
                      libvulkan-dev:i386 \
                      libwayland-dev:i386 \
                      libxcomposite1:i386 \
                      libxkbregistry-dev:i386 \
                      libxpm-dev:i386 \
                      libxxhash-dev:i386 \
                      libyuv-dev:i386 \
                      linux-libc-dev:i386 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
                      arch-install-scripts \
                      autossh \
                      autoconf \
                      automake \
                      bash \
                      bc \
                      binutils-dev \
                      bison \
                      bsdextrautils \
                      ca-certificates \
                      clang++-19 \
                      clang-19 \
                      cmake \
                      debootstrap \
                      elfutils \
                      flex \
                      g++ \
                      g++-12-aarch64-linux-gnu \
                      g++-12-multilib \
                      g++-12-multilib-i686-linux-gnu \
                      g++-12-multilib-mips-linux-gnu \
                      g++-12-multilib-mips64el-linux-gnuabi64 \
                      g++-12-multilib-mipsel-linux-gnu \
                      gawk \
                      gcc \
                      gcc-12-aarch64-linux-gnu \
                      gcc-12-multilib \
                      gcc-12-multilib-i686-linux-gnu \
                      gcc-12-multilib-mips-linux-gnu \
                      gcc-12-multilib-mips64el-linux-gnuabi64 \
                      gcc-12-multilib-mipsel-linux-gnu \
                      git \
                      glib2.0-dev \
                      gmsl \
                      graphviz \
                      gstreamer1.0-dev \
                      hostname \
                      libavcodec-dev \
                      libavformat-dev \
                      libc6-dev-i386 \
                      libclang-19-dev \
                      libegl1-mesa-dev \
                      libfontconfig-dev \
                      libfontconfig-dev \
                      libfreetype-dev \
                      libgdm-dev \
                      libglib2.0-dev \
                      libgnutls28-dev \
                      libgraph-easy-perl \
                      libgstreamer1.0-dev \
                      libkeyutils-dev \
                      libosmesa6-dev \
                      libpcre2-dev \
                      libpfm4-dev \
                      libsdl2-dev \
                      libtinfo-dev \
                      libtool \
                      libtraceevent-dev \
                      libunwind-dev \
                      liburing-dev \
                      libvulkan-dev \
                      libwayland-dev \
                      libxkbregistry-dev \
                      libxml2-dev \
                      libz3-dev \
                      libzstd-dev \
                      lld-19 \
                      llvm-19-dev \
                      locales \
                      make \
                      meson \
                      mingw-w64 \
                      ninja-build \
                      openssh-client \
                      parted \
                      pkg-config \
                      pkgconf \
                      python3-dev \
                      python3-libtmux \
                      python3-venv \
                      qemu-system \
                      rustc \
                      sed \
                      ssh \
                      sudo \
                      tar \
                      tmux \
                      unzip \
                      vim-common \
                      xfsprogs \
                      xxd && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales

RUN echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list && \
    eatmydata apt-get update && \
    eatmydata apt-get install --no-install-recommends -y -t bookworm-backports meson libgl1-mesa-dri && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mipsel && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:mipsel \
                      linux-libc-dev:mipsel \
                      libglib2.0-dev:mipsel && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mips64el && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:mips64el \
                      linux-libc-dev:mips64el \
                      libglib2.0-dev:mips64el && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture arm64 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
                      libc6-dev:arm64 \
                      linux-libc-dev:arm64 \
                      libglib2.0-dev:arm64 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y

ADD . /jove/
RUN /jove/scripts/ci_build_carbon_copy.sh
RUN patch -p0 -d / -i /jove/patches/meson.diff
RUN patch -p1 -d /jove/wine -i /jove/patches/wine.diff
RUN patch -p1 -d /jove/boost/libs/graph -i /jove/patches/boost-graph.diff
RUN patch -p1 -d /jove/boost/libs/interprocess -i /jove/patches/boost-interprocess.diff
RUN patch -p1 -d /jove/boost/libs/unordered -i /jove/patches/boost-unordered.diff
RUN /jove/scripts/build/build.sh 6
RUN /jove/scripts/ci_install.sh
