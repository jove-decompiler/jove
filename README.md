# Examples
## `ls`
```bash
cd jove/bin

jove-init -o $HOME/.jove/ls --git /usr/bin/ls
jove-bootstrap -d $HOME/.jove/ls /usr/bin/ls -q --syscalls -- -la /

mkdir ls.sysroot
sudo jove-loop -d $HOME/.jove/ls --sysroot ls.sysroot /usr/bin/ls -- -la /
```
For debian-based systems you can run the following to install all needed debug symbols (remember to re-run jove-init)
```bash
sudo apt-get install debian-goodies

for b in $(jove-dump $HOME/.jove/ls --list-binaries) ; do find-dbgsym-packages $b ; done
```
If you installed `easy-graph`, do this to view control-flow-graphs of every function in libc:
```bash
for f in $(jove-dump --list-functions=libc $HOME/.jove/ls) ; do jove-cfg -d $HOME/.jove/ls -b libc $f ; sleep 10s ; done
```

## `dnsmasq`
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

sudo jove-init -o $HOME/.jove/dnsmasq --git /usr/sbin/dnsmasq
sudo jove-bootstrap -d $HOME/.jove/dnsmasq -q --syscalls /usr/sbin/dnsmasq -- -C mydnsmasq.conf -d -q -k --dhcp-alternate-port

mkdir dnsmasq.sysroot
cp mydnsmasq.conf dnsmasq.sysroot/

sudo ./jove-loop -d $HOME/.jove/dnsmasq --sysroot dnsmasq.sysroot /usr/sbin/dnsmasq -- -C /mydnsmasq.conf -d -q -k --dhcp-alternate-port
```

## `miniupnpd`
```bash
sudo apt-get install miniupnpd

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

sudo jove-init -o $HOME/.jove/miniupnpd --git /usr/sbin/miniupnpd
sudo jove-bootstrap -d $HOME/.jove/miniupnpd -q --syscalls /usr/sbin/miniupnpd -- -d -f /myminiupnpd.conf

mkdir miniupnpd.sysroot
cp myminiupnpd.conf miniupnpd.sysroot/
mkdir -p miniupnpd.sysroot/var/run

sudo ./jove-loop -d $HOME/.jove/miniupnpd --sysroot miniupnpd.sysroot /usr/sbin/miniupnpd -- -d -f /myminiupnpd.conf
```

## `nginx`
```bash
sudo apt-get install nginx-light
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

sudo apt-get install nginx-light

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
# Building
```bash
sudo apt-get update
sudo apt-get install cmake ninja-build easy-graph graphviz libxml2
# on archlinux: sudo pacman -Syu ninja cmake graphviz libxml2
sudo apt-get build-dep llvm
sudo apt-get build-dep libz3-dev

cd jove/
git submodule update --init --recursive

cd third_party/
make build-llvm

cd ..
make -j$(nproc)
```
