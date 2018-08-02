---
title: Linux网络设置
author: DuanEnJian
tags:
  - 其他
  - Linux
categories:
  - 运维
abbrlink: 3139455287
date: 2017-12-27 21:29:00
---
# dns设置
```
#修改文件 vi /etc/resolv.conf
#修改内容
nameserver 114.114.114.114
nameserver 8.8.8.8
```

<!-- more -->
# ip设置
```
#修改文件: vi /etc/sysconfig/network-scripts/ifcfg-eth0
#修改内容
DEVICE=eth0 #描述网卡对应的设备别名，例如ifcfg-eth0的文件中它为eth0
BOOTPROTO=static #设置网卡获得ip地址的方式，可能的选项为static，dhcp或bootp，分别对应静态指定的 ip地址，通过dhcp协议获得的ip地址，通过bootp协议获得的ip地址
BROADCAST=192.168.1.255 #对应的子网广播地址
HWADDR=00:0C:29:68:AD:61 #对应的网卡物理地址
IPADDR=192.168.1.99 #如果设置网卡获得 ip地址的方式为静态指定，此字段就指定了网卡对应的ip地址 
IPV6INIT=no
IPV6_AUTOCONF=no
NETMASK=255.255.255.0 #网卡对应的网络掩码
NETWORK=192.168.1.0 #网卡对应的网络地址
ONBOOT=yes #系统启动时是否设置此网络接口，设置为yes时，系统启动时激活此设备
DNS1=114.114.114.114
DNS2=8.8.8.8
#注:在centos6.3及以上版本，若/etc/resolv.conf设置好之后，出现域名还不能解析的情况下，则在此文件加上面红色部分
```
# gateway网关设置
```
#修改文件: vi /etc/sysconfig/network
#修改内容
NETWORKING=yes #表示系统是否使用网络，一般设置为yes。如果设为no，则不能使用网络，而且很多系统服务程序将无法启动
HOSTNAME=localhost.localdomain #设置本机的主机名，这里设置的主机名要和/etc/hosts中设置的主机名对应
GATEWAY=192.168.1.253 #ip网关地址，跟据你的实际情况设置
```

注:    
- 在vmware虚拟机中，通过以上设置;且在网络适配器选择“桥接模式”就可和你电脑的系统相互通信，还可访问外网哦(前提是你的外网可以访问)
- 以上都是修改的配置文件,也就是说系统重启后也会生效；下面说一些临时的修改方法（重启系统会失效）
```
修改IP地址 ifconfig eth0 192.168.0.2 netmask 255.255.255.0 
修改网关 route add default gw 192.168.0.1 dev eth0 
```