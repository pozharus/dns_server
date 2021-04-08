# How to use

Structure:
conf.json - file with configuration of server;
dns.json - DNS zones file;
dns_server.py - server;

System configuration:
Using 127.0.0.1#53 adress in conf.json;
If port are beasy use this guide to free it:
https://andreyex.ru/ubuntu/kak-osvobodit-port-53-ispolzuemyj-systemd-resolved-v-ubuntu/

Conf python & start server: 
sudo pip3 install dnslib
sudo python3 dns_server.py

Examples of queries:
dig @127.0.0.1 pikabu.ru 
dig @127.0.0.1 facebook.com
dig @127.0.0.1 habr.com 
dig @127.0.0.1 linkedin.com
dig @127.0.0.1 habr.com TXT habr.com A
dig @127.0.0.1 linkedin.com TXT linkedin.com A

