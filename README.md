# Download
https://images.aarno-labs.com/jove/

## Installation
```bash
# (Assuming this is an x86_64 host)
mkdir /opt/jove
tar -xvf jove.v0.78.2b7988cc-x86_64-multiarch.tar.xz -C /opt/jove

# Choose one of the target architectures:
export PATH=$PATH:/opt/jove/i386
export PATH=$PATH:/opt/jove/x86_64
export PATH=$PATH:/opt/jove/mips32
export PATH=$PATH:/opt/jove/mips64
export PATH=$PATH:/opt/jove/aarch64
```

Some tools, such as `jove-bootstrap`, will only work if the target architecture matches the host's.

# Examples

## `ls` (debian)
```bash
jove-init -o ls.jv --git /usr/bin/ls
jove-bootstrap -d ls.jv /usr/bin/ls -s -- -la /

mkdir ls.sysroot
jove-loop -d ls.jv --sysroot ls.sysroot /usr/bin/ls -- -la /
```
For debian-based systems you can run the following to install all needed debug symbols (remember to re-run jove-init)
```bash
apt-get install debian-goodies

for b in $(jove-dump $HOME/.jove/ls --list-binaries) ; do find-dbgsym-packages $b ; done
```
If you installed `easy-graph`, do this to view control-flow-graphs of every function in libc:
```bash
for f in $(jove-dump --list-functions=libc $HOME/.jove/ls) ; do jove-cfg -d $HOME/.jove/ls -b libc $f ; sleep 10s ; done
```

## `dnsmasq` (debian)
```bash
sudo apt-get install dnsmasq

cd jove/bin

cat > mydnsmasq.conf <<EOF
domain-needed
bogus-priv
enable-ra
port=0
dhcp-range=::2,::500, constructor:localhost, 64, 12h
interface=localhost
listen-address=127.0.0.1
dhcp-range=localhost,172.0.0.3,172.0.0.150,100h
dhcp-leasefile=/tmp/dnsmasq.leases
EOF

jove-init -o dnsmasq.jv --git /usr/sbin/dnsmasq
jove-bootstrap -d dnsmasq.jv -s /usr/sbin/dnsmasq -- -C mydnsmasq.conf -d -q -k --dhcp-alternate-port

mkdir dnsmasq.sysroot
cp mydnsmasq.conf dnsmasq.sysroot/

jove-loop -d dnsmasq.jv --sysroot dnsmasq.sysroot /usr/sbin/dnsmasq -- -C /mydnsmasq.conf -d -q -k --dhcp-alternate-port
```

## `miniupnpd` (debian)
```bash
apt-get install miniupnpd

cd jove/bin

cat > myminiupnpd.conf <<EOF
ext_ifname=xl1
listening_ip=0.0.0.0
port=5555
enable_natpmp=yes
bitrate_up=1000000
bitrate_down=10000000
secure_mode=yes
system_uptime=yes
notify_interval=60
clean_ruleset_interval=600
uuid=fc4ec57e-b051-11db-88f8-0060085db3f6
serial=12345678
model_number=1
allow 1024-65535 192.168.0.0/24 1024-65535
allow 1024-65535 192.168.1.0/24 1024-65535
allow 1024-65535 192.168.0.0/23 22
allow 12345 192.168.7.113/32 54321
allow 0-65535 0.0.0.0/0 0-65535
EOF

jove-init -o miniupnpd.jv --git /usr/sbin/miniupnpd
jove-bootstrap -d miniupnpd.jv -s /usr/sbin/miniupnpd -- -d -f /myminiupnpd.conf

mkdir miniupnpd.sysroot
cp myminiupnpd.conf miniupnpd.sysroot/
mkdir -p miniupnpd.sysroot/var/run

jove-loop -d miniupnpd.jv --sysroot miniupnpd.sysroot /usr/sbin/miniupnpd -- -d -f /myminiupnpd.conf
```

## `nginx` (debian)
```bash
sudo apt-get install nginx-light
cd jove/bin

cat > mynginx.conf <<EOF
worker_processes  1;

daemon off;
master_process off;

error_log stderr;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    server {
        listen       5000;
        server_name  localhost;

        location / {
            root   html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
EOF

sudo apt-get install nginx-light

jove-init -o nginx.jv --git /usr/sbin/nginx
jove-bootstrap -d nginx.jv -s /usr/sbin/nginx -- -c mynginx.conf

mkdir nginx.sysroot
cp mynginx.conf nginx.sysroot/
mkdir -p nginx.sysroot/usr/share/
mkdir -p nginx.sysroot/var/lib/nginx
mkdir -p nginx.sysroot/var/log/nginx
cp -r /usr/share/nginx nginx.sysroot/usr/share/

sudo jove-loop -d nginx.jv --sysroot nginx.sysroot /usr/sbin/nginx -- -c /mynginx.conf
```
## `httpd` (Netgear WNDR4500)
When running jove under firmadyne, use the version of `libnvram` in the third_party directory.

Assuming the plan is to cross-recompile from an x86_64 host to a mips32 target:
```bash
export PATH=$PATH:$HOME/jove/bin/mips32
nice jove-server --tmpdir ~/tmp --port 9999
```
Then, start the QEMU emulation (I prefer passing "-serial pty" to QEMU). Blindly paste
```bash
/usr/sbin/telnetd -p3333 -l/bin/sh
```
And then get a shell
```bash
telnet 192.168.1.1 3333
```

We assume /mnt is the root directory of a mipsel jove installation.
```bash
export PATH=$PATH:/mnt/bin/mips32

jove-init -o /mnt/httpd.jv /usr/sbin/httpd

jove-bootstrap -d /mnt/httpd.jv -e /usr/sbin/httpd -- -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
# or, attach to an existing process
jove-bootstrap -d /mnt/httpd.jv -e /usr/sbin/httpd --attach 503

# 
```

assuming host is network-connected to guest with IP 192.168.1.2, run in the guest:
```bash
jove-loop -d /mnt/wndr4500/httpd.jv --connect 192.168.1.2:9999 --sysroot /mnt/wndr4500/sysroot httpd.sysroot -x /usr/sbin/httpd -- -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

Note: passing `-x` instructs `jove-loop` to only recompile the executable itself (not including any shared libraries it is linked to). This makes it possible to run the recompiled program without the use of a chroot.

# Building
```bash
# on debian testing:
apt install g++-multilib-i686-linux-gnu g++-multilib-mipsel-linux-gnu g++-multilib-mips64el-linux-gnuabi64 g++-aarch64-linux-gnu libboost-all-dev cmake ninja-build easy-graph graphviz libxml2 libgraph-easy-perl gmsl libz3-dev
apt-get build-dep llvm

# on archlinux: yay -Syu ninja cmake graphviz libxml2 gmsl perl-graph-easy

cd jove/
git submodule update --init --recursive

cd third_party/
ulimit -s unlimited
make build-llvm

cd ..
make -j$(nproc)
```

# FAQ
### What is jove?
A: Given a dynamically linked executable `E`, jove produces source code for `E` that, when compiled and run, produce the same outputs.
### What's the catch?
A: You have to run the program in question under `jove-bootstrap` (the ptrace(2)-based dynamic analysis) for all the inputs that you should expect of the recompiled program to take.
