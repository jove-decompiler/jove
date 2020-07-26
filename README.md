# Getting started
## Tested environments
- Debian 11 (i386, x86_64, mipsel, mips64el)
- Arch Linux (x86_64)
- Arch Linux 32 (i386)
- ArchLinuxARM (arm64)
## Prerequisites
- `gcc` (capable of building LLVM)
- `ninja`
- `cmake`
- `python`
- `libxml2`
- `z3`
- `python` `yaml` module
## Optional
- `easy-graph` ([debian](https://packages.debian.org/testing/libgraph-easy-perl), [AUR](https://aur.archlinux.org/packages/perl-graph-easy/))
## Building llvm
```bash
cd jove/
git submodule update --init --recursive
make -C third_party/ build-llvm
```
## Building jove
```bash
cd jove/
make
```
# Examples
## `ls`
```bash
cd jove/bin

jove-init -o $HOME/.jove/ls --git /usr/bin/ls
jove-bootstrap -d $HOME/.jove/ls /usr/bin/ls -q --syscalls -- -la /

mkdir ls.sysroot
sudo jove-loop -d $HOME/.jove/ls --sysroot ls.sysroot /usr/bin/ls -- -la /
```
Tip: For debian-based systems you can run the following to install all needed debug symbols (remember to re-run jove-init)
```bash
for b in $(jove-dump $HOME/.jove/ls --list-binaries) ; do find-dbgsym-packages $b ; done
```
After installing `easy-graph`, try this
```bash
for f in $(jove-dump --list-functions=libc $HOME/.jove/ls) ; do echo $f ; jove-cfg -d $HOME/.jove/ls -b libc $f ; sleep 10s ; done
```

## `dnsmasq`
```bash
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

sudo jove-init -o $HOME/.jove/dnsmasq --git /usr/sbin/dnsmasq
sudo jove-bootstrap -d $HOME/.jove/dnsmasq -q --syscalls /usr/sbin/dnsmasq -- -C mydnsmasq.conf -d -q -k --dhcp-alternate-port

mkdir dnsmasq.sysroot
cp mydnsmasq.conf dnsmasq.sysroot/

sudo ./jove-loop -d $HOME/.jove/dnsmasq --sysroot dnsmasq.sysroot /usr/sbin/dnsmasq -- -C /mydnsmasq.conf -d -q -k --dhcp-alternate-port
```

## `nginx`
```bash
cd jove/bin

cat > mynginx.conf <<EOF
worker_processes  1;

daemon off;
master_process off;

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

sudo jove-init -o $HOME/.jove/nginx --git /usr/sbin/nginx
sudo jove-bootstrap -d $HOME/.jove/nginx -q --syscalls /usr/sbin/nginx -- -c mynginx.conf

mkdir nginx.sysroot
cp mynginx.conf nginx.sysroot/
mkdir -p nginx.sysroot/usr/share/
mkdir -p nginx.sysroot/var/lib/nginx
mkdir -p nginx.sysroot/var/log/nginx
cp -r /usr/share/nginx nginx.sysroot/usr/share/

sudo jove-loop -d $HOME/.jove/nginx --sysroot nginx.sysroot /usr/sbin/nginx -- -c /mynginx.conf
```
