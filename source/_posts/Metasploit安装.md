---
title: Metasploit安装
author: DuanEnJian
tags:
  - Metasploit
  - Linux
categories:
  - 其他
abbrlink: 237147173
date: 2017-12-27 21:25:00
---
# 安装pgsql
```
sudo apt-get install ruby
sudo apt-get install postgresql-9.3 postgresql-client-9.3
```

<!-- more -->
# 修改pgsql用户密码
```
sudo su postgres  
psql postgres  
alter user postgres with password 'new password'  
sudo -u postgres psql postgres
```

# 连接Pgsql
```
sudo -u postgres psql -U postgres -d postgres -h 127.0.0.1
```
# 安装Metasploit
```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && ./msfinstall
msfconsole              #启动msf
db_connect postgres:hehehe@127.0.0.1/msfdb
db_status                # 查看数据库连接状态
```