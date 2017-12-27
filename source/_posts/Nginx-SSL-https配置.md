title: Nginx SSL-https配置
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
date: 2017-12-27 21:37:00
---
要保证Web浏览器到服务器的安全连接，HTTPS几乎是唯一选择。HTTPS其实就是HTTP over SSL，也就是让HTTP连接建立在SSL安全连接之上。
# nginx配置说明
```nginx
listen 80; //监听80端口
listen 443;//监听443端口
ssl on; //开启SSL
ssl_certificate /usr/local/nginx/conf/server.crt; //配置CRT路径
ssl_certificate_key /usr/local/nginx/conf/server.key; //配置KEY路径
```
最近在研究nginx，整好遇到一个需求就是希望服务器与客户端之间传输内容是加密的，防止中间监听泄露信息，但是去证书服务商那边申请证书又不合算，因为访问服务器的都是内部人士，所以自己给自己颁发证书，忽略掉浏览器的不信任警报即可。下面是颁发证书和配置过程。
# 安装openssl和openssl-devel
```bash
//首先确保机器上安装了openssl和openssl-devel
#yum install openssl
#yum install openssl-devel
```
# 颁发证书
```bash
#cd /usr/local/nginx/conf
#openssl genrsa -des3 -out server.key 1024
#openssl req -new -key server.key -out server.csr
#openssl rsa -in server.key -out server_nopwd.key
#openssl x509 -req -days 365 -in server.csr -signkey server_nopwd.key -out server.crt
```
# 配置nginx
```nginx
//至此证书已经生成完毕，下面就是配置nginx
server {
    listen 443;
    ssl on;
    ssl_certificate  /usr/local/nginx/conf/server.crt;
    ssl_certificate_key  /usr/local/nginx/conf/server.key;
}
```
然后重启nginx即可。
ps： 如果出现“[emerg] 10464#0: unknown directive "ssl" in /usr/local/nginx-0.6.32/conf/nginx.conf:74”
则说明没有将ssl模块编译进nginx，在configure的时候加上“--with-http_ssl_module”即可