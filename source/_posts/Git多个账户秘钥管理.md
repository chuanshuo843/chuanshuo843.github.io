title: Git多个账户秘钥管理
author: DuanEnJian
tags:
  - Git
categories:
  - 开发
  - ''
date: 2018-07-26 15:51:00
---
由于公司团队使用 GitLab 来托管代码，同时，个人在 Github 上还有一些代码仓库，可公司邮箱与个人邮箱是不同的，由此产生的 SSH key 也是不同的，这就造成了冲突 ，文章提供此类问题的解决方案：如何在一台机器上面同时使用 Github 与 Gitlab 的服务？

# 生成ssh key
```
#生成新的ssh key并命名为id_rsa_gs
[root@localhost cps]# ssh-keygen -t rsa -C "youremail@email.com" -f ~/.ssh/id_rsa_gs
[root@localhost cps]# ls ~/.ssh/
config  id_rsa  id_rsa_gs  id_rsa_gs.pub  id_rsa.pub  known_hosts
```
# 远程主机添加公钥

![upload successful](/images/image.png)
# 编辑ssh的cofnig文件
```
vim ~/.ssh/config

# Default 默认配置，一般可以省略
      Host github.com
      Hostname github.com
      User git
      Identityfile ~/.ssh/id_rsa
# Company 给一个新的Host称呼
      Host 192.168.0.31  // 主机名字，不能重名
      HostName 192.168.0.31   // 主机所在域名或IP
      User git  // 用户名称
      IdentityFile ~/.ssh/id_rsa_gs  // 私钥路径
```
# 测试连接
```
[root@localhost cps]# ssh -T git@192.168.0.31
Welcome to GitLab, HAHA!
```
# 修改本地git配置文件
```
[root@localhost cps]# vim .git/config 
[remote "origin"]
    url = git@192.168.0.31:fe/cps.git #对应上面的用户@对应上面的Host:项目地址
    fetch = +refs/heads/*:refs/remotes/origin/*
```