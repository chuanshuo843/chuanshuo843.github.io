title: ITerm2快捷登录
author: o时过境迁心难沉
abbrlink: e774f456
tags:
  - Linux
categories:
  - 开发
date: 2018-09-19 15:37:00
---
windows里有个Xshell非常的方便好使，因为它能保存你所有的ssh登录帐号信息。MAC下并没有xshell，有些也提供这样的功能，但效果都不好。iterm2是很好的终端，但却不能很好的支持多profiles，当要管理的机器较多时，就比较麻烦了。好在它有profiles设置，只是不能保存ssh登录帐号及密码，它还提供了加载profiles时执行外部命令的功能

<!-- more -->
# 方案一

## 普通配置

Iterm2 profiles配置
```
~/.ssh/login_shell 账号 服务器地址 密码
```
登录脚本
```
localhost:.ssh duanenjian$ vim login_shell 
#!/usr/bin/expect
 
set timeout 30
if [llength $argv]==4 {
	spawn ssh [lindex $argv 0]@[lindex $argv 1] -i [lindex $argv 3]
}
if [llength $argv]==3 {
	spawn ssh [lindex $argv 0]@[lindex $argv 1]
}
expect {
        "(yes/no)?"
        {send "yes\n";exp_continue}
        "password:"
        {send "[lindex $argv 2]\n"}
}
interact
```
## 跳板机配置
Iterm2 profiles配置
```
~/.ssh/login_jumpserver 账号  服务器地址 PEM文件密码 PEM文件地址
```
登录脚本
```
localhost:.ssh duanenjian$ vim login_jumpserver 
#!/usr/bin/expect

spawn ssh [lindex $argv 0]@[lindex $argv 1] -i [lindex $argv 3]
expect {
  "(yes/no)?" {
    send "yes\r"
    exp_continue
  }
  "Enter passphrase for key *:*" {
    send "[lindex $argv 2]\n"
  }
}
interact
```
![Iterm2_1](/images/iterm_1.png)
![Iterm2_2](/images/iterm_2.png)
![Iterm2_3](/images/iterm_3.png)

# 方案二

## 普通配置
```
iterm2 ------> Profiles ------>  当前配置的profiles ------> General
```
![peizi_1](/images/WX20180929-114509.png)

```
iterm2 ------> Profiles ------>  当前配置的profiles ------> Advanced ------> Triggers的Edit按钮
//自动登录
Regular expression:password:
Action: Send Text
Parameters: 密码 + /r
//rz sz 上传下载
Regular expression:\*\*B0100
Action: Run Silent Coprocess
Parameters: /usr/local/bin/iterm2-send-zmodem.sh

Regular expression:\*\*B00000000000000
Action: Run Silent Coprocess
Parameters: /usr/local/bin/iterm2-recv-zmodem.sh
```
![peizi_2](/images/WX20180929-114601.png)
## 跳板机配置

```
iterm2 ------> Profiles ------>  当前配置的profiles ------> General
```
![peizi_1](/images/WX20180929-114636.png)

```
iterm2 ------> Profiles ------>  当前配置的profiles ------> Advanced ------> Triggers的Edit按钮
//自动登录
Regular expression:password:
Action: Send Text
Parameters: 密码 + /r
//rz sz 上传下载
Regular expression:\*\*B0100
Action: Run Silent Coprocess
Parameters: /usr/local/bin/iterm2-send-zmodem.sh

Regular expression:\*\*B00000000000000
Action: Run Silent Coprocess
Parameters: /usr/local/bin/iterm2-recv-zmodem.sh
```
![peizi_2](/images/WX20180929-114701.png)

# rz sz 上传下载配置
```
//安装lrzsz
brew install lrzsz
//下载文件
在https://github.com/mmastrac/iterm2-zmodem上将iterm2-send-zmodem.sh 和 iterm2-recv-zmodem.sh脚本下载下来并放到/usr/local/bin/目录下，注意赋予脚本执行的权限
//iterm2配置
iterm2 ------> Profiles ------>  当前配置的profiles ------> Advanced ------> Triggers的Edit按钮
//上传
Regular expression:\*\*B0100
Action: Run Silent Coprocess
Parameters: /usr/local/bin/iterm2-send-zmodem.sh
//下载
Regular expression:\*\*B00000000000000
Action: Run Silent Coprocess
Parameters: /usr/local/bin/iterm2-recv-zmodem.sh
```
![peizi_2](/images/WX20180929-114701.png)