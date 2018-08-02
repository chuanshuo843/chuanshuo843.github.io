---
title: Linux终端美化之ZSH
author: DuanEnJian
tags:
  - 其他
  - Linux
categories:
  - 其他
abbrlink: 3194097614
date: 2017-12-28 16:58:00
---
Zsh是一个Linux用户很少使用的shell，这是由于大多数Linux产品安装，以及默认使用bash shell。几乎每一款Linux产品都包含有zsh，通常可以用apt-get、urpmi或yum等包管理器进行安装
<!-- more -->
# 安装ZSH
```bash
sudo dnf install zsh
```
# 安装oh-my-zsh
oh-my-zsh是基于zsh的功能做了一个扩展，方便的插件管理、主题自定义，以及漂亮的自动完成效果。
```bash
#CURL方式(二选一)
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
#WGET方式(二选一)
sh -c "$(wget https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
```
# 安装powerline
Powerline是vim的状态行插件，并为其他几个应用程序提供状态行和提示，包括zsh，bash，tmux，IPython，Awesome，i3和Qtile。
## For Shell
```bash
#安装powerline
sudo dnf install powerline
#编辑 ~/.bashrc 添加
if [ -f `which powerline-daemon` ]; then
  powerline-daemon -q
  POWERLINE_BASH_CONTINUATION=1
  POWERLINE_BASH_SELECT=1
  . /usr/share/powerline/bash/powerline.sh
fi
```
## For Tmux
```bash
#安装tmux-powerline
sudo dnf install tmux-powerline
#编辑~/.tmux.conf 添加
source "/usr/share/tmux/powerline.conf"
```
## For VIM
```bash
#安装vim-plugin-powerline
sudo dnf install vim-plugin-powerline
#编辑~/.vimrc 添加
python from powerline.vim import setup as powerline_setup
python powerline_setup()
python del powerline_setup
set laststatus=2
set t_Co=256
```
某些更改可能需要您重新加载会话或可能重新启动守护程序：powerline-daemon --replace

# oh-my-zsh配置
完成配置后重启终端生效 
[oh-my-zsh主题列表](https://github.com/robbyrussell/oh-my-zsh/wiki/Themes)
[oh-my-zsh插件列表](https://github.com/robbyrussell/oh-my-zsh/wiki/Plugins)
```bash
#编辑~/.zshrc文件
vim ~/.zshrc
#配置主题(推荐使用:agnoster)
ZSH_THEME="agnoster"
#配置插件
plugins=(git history docker fedora dnf composer man systemd pip redis-cli go cp node npm perl yum python man)
#开启自动更新
DISABLE_AUTO_UPDATE="true"
#最后执行
source .zshrc
```
# 效果图
{% asset_img 5db16f6db6e0cc50fe98f8c57c659d2b.gif 效果图01 %}
{% asset_img 8b96a51c781e4334ad73811e209b1ee7.jpeg 效果图02 %}
{% asset_img b70b72d1fa44f8368668d829502804ba.jpeg 效果图03 %}
