FROM debian:testing

LABEL maintainer aeden@aarno-labs.com

# Change this as needed for your jenkins installation or if things change in
# hippo
ARG jenkins_uid=111
ARG jenkins_gid=113

#------------------------------------------------------------------------------
# Install system packages
#------------------------------------------------------------------------------
USER root

RUN apt-get update
# These are required for adding the Docker repo
RUN apt-get -yq install apt-transport-https ca-certificates curl gnupg lsb-release
RUN apt-get -yq install build-essential make unzip autoconf automake libtool sudo vim-common git
RUN apt-get -yq install \
        binutils-dev \
        g++-multilib-i686-linux-gnu \
        g++-multilib-mipsel-linux-gnu \
        g++-multilib-mips64el-linux-gnuabi64 \
        g++-aarch64-linux-gnu \
        libboost-all-dev \
        cmake \
        ninja-build \
        graphviz libxml2 libgraph-easy-perl gmsl libz3-dev libtinfo-dev pkg-config libglib2.0-dev

RUN useradd aarno -G sudo,adm -U --create-home \
    && echo "aarno ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN groupadd -g $jenkins_gid jenkins \
    && useradd jenkins -g $jenkins_gid -u $jenkins_uid -r -G sudo,adm -d /var/lib/jenkins --create-home \
    && echo "jenkins ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER jenkins
WORKDIR /var/lib/jenkins
CMD [ "/bin/bash" ]
