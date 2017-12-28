title: Fedora24使用笔记
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
date: 2017-12-28 17:05:00
---
Fedora 是一个 Linux 发行版，是一款由全球社区爱好者构建的面向日常应用的快速、稳定、强大的操作系统。它允许任何人自由地使用、修改和重发布，无论现在还是将来。它由一个强大的社群开发，这个社群的成员以自己的不懈努力，提供并维护自由、开放源码的软件和开放的标准。Fedora 项目由 Fedora 基金会管理和控制，得到了 Red Hat 的支持。
<!-- more -->
# 更新系统 
```bash
dnf update
```
# 添加RPM Fusion源
```bash
dnf install --nogpgcheck http://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-24.noarch.rpm
dnf install --nogpgcheck http://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-24.noarch.rpm 
```
# 添加FZUG源
```bash
dnf config-manager --add-repo=http://repo.fdzh.org/FZUG/FZUG.repo
```
# 添加adobe源
```bash
dnf install --nogpgcheck http://linuxdownload.adobe.com/linux/x86_64/adobe-release-x86_64-1.0-1.noarch.rpm
```
# 安装GNOME调整工具
```bash
dnf install gnome-tweak-tool
```
# 安装User Themes扩展
https://extensions.gnome.org/extension/19/user-themes/
# 添加OSX-Arc-White主题
```bash
wget https://dl.opendesktop.org/api/files/download/id/1470839268/OSX-Arc-White-v-1.1.tar.gz
tar -zxvf OSX-Arc-White-v-1.1.tar.gz
sudo mv -rf OSX-Arc-White /usr/share/themes/
```
# 添加Mine-Yosemite图标
[Mine-icon-themes.tar.gz](Mine-icon-themes.tar.gz)
```bash
tar -zxvf Mine-icon-themes.tar.gz
sudo mv -rf Mine-Yosemite /usr/share/icons/
```
# 安装shadowsocks-qt5
参考:
https://github.com/shadowsocks/shadowsocks-qt5/wiki/%E5%AE%89%E8%A3%85%E6%8C%87%E5%8D%97
```bash
sudo dnf copr enable librehat/shadowsocks
sudo dnf update
sudo dnf install shadowsocks-qt5
```
# 安装MySQL Workbench
```bash
sudo dnf install --nogpgcheck http://dev.mysql.com/get/mysql-community-release-fc21-6.noarch.rpm
sudo dnf install mysql-workbench-community
```
# 安装Manaco字体
```bash
cd ~
git clone https://github.com/cstrap/monaco-font.git
sudo bash monaco-font/install-font-centos.sh http://usystem.googlecode.com/files/MONACO.TTF
```
# 效果展示
{% asset_img 964398adbdfee356cc91245ecc0f2819.jpg 桌面效果图 %}
{% asset_img d0986899c76c3e0c9a1db1ec3a409cbc.jpg 应用列表效果图 %}
{% asset_img e2c9d0c55ef130ec72cdceb41ecbbcbf.jpg 文件夹效果图 %}