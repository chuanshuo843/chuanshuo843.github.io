title: Shadowsocks之科学上网
author: DuanEnJian
tags:
  - 其他
categories:
  - 其他
date: 2017-12-28 16:46:00
---
Shadowsocks的运行原理与其他代理工具基本相同，使用特定的中转服务器完成数据传输。
在服务器端部署完成后，用户需要按照指定的密码、加密方式和端口使用客户端软件与其连接。在成功连接到服务器后，客户端会在用户的电脑上构建一个本地Socks5代理。浏览网络时，网络流量会被分到本地socks5代理，客户端将其加密之后发送到服务器，服务器以同样的加密方式将流量回传给客户端，以此实现代理上网。
<!-- more -->
# Shadowsocks

## Shadowsocks服务端

[(自建服务器需要)Shadowsocks服务端](https://github.com/mengskysama/shadowsocks-rm)

## OS X 客户端

[shadowsocks-gui](https://github.com/shadowsocks/shadowsocks-gui) - Cross-platform GUI powered by node and Webkit
[GoAgentX](https://github.com/ohdarling/GoAgentX) - OS X client, with GUI
[Shadowsocks for Mac](https://github.com/shadowsocks/shadowsocks-iOS/wiki/Shadowsocks-for-OSX-Help) - Shadowsocks GUI designed for OS X 10.7+

## Windows 客户端

[shadowsocks-gui](https://github.com/shadowsocks/shadowsocks-gui) - Cross-platform GUI powered by node and Webkit
[shadowsocks-csharp](https://github.com/clowwindy/shadowsocks-csharp) - Windows version with GUI
[Yingwa](https://github.com/dallascao/yingwa) - Shadowsocks Windows client

## Linux 客户端

[shadowsocks-gui](https://github.com/shadowsocks/shadowsocks-gui) - Cross-platform GUI powered node and by Webkit

## iOS 客户端

[shadowsocks-iOS](https://github.com/shadowsocks/shadowsocks-iOS) - All devices, web browser, global proxy with some restrictions
[MobileShadowSocks](https://github.com/linusyang/MobileShadowSocks) - Jailbroken devices only, global proxy with no restriction

## Android 客户端

[shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android)

## 路由器 / Router 客户端

[shadowsocks-openwrt](https://github.com/haohaolee/shadowsocks-openwrt) - works on OpenWRT routers
[极玩路由器](http://geewan.com/?r=4012)

## 实验环境

[shadowsocks-ruby](https://github.com/clowwindy/shadowsocks-ruby) Ruby version
[shadowsocks-chromeapp](https://github.com/clowwindy/shadowsocks-chromeapp) - Chrome App

# SwitchyOmega

## SwitchyOmega插件

[SwitchyOmega.crx](6bd47d982c42fd691065147746042f1d.crx)

## SwitchyOmega备份

[OmegaOptions.bak](d317d514f1335ac696f58a5630168b82.bak)

## 规则列表网址

[https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt](https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt)

# Shadowsocks账号

## 自建服务器

[搬瓦工](https://bandwagonhost.com/)

## 网络获取

百度or谷歌搜索：科学上网
百度or谷歌搜索：Shadowsocks
[ss-link](https://www.ss-link.me)
[ACGSS](https://acgapp.moe)
    
# 图解说明

## 原理图
{% asset_img 821ae3ca15de97811df2c9fd39707bad.jpg 原理图 %}
## 界面图
{% asset_img 7b05a45dcf3915cc8ccf8d5575ecca38.png 界面图 %}