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

# 普通配置

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
# 跳板机配置
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