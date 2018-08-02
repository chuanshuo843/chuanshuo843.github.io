---
title: "设置mysql重启后,\_Events自启动"
author: DuanEnJian
tags:
  - MySQL
categories:
  - 数据库
abbrlink: 2934597634
date: 2017-12-27 21:16:00
---
mysql5.1版本开始引进event概念。event既“时间触发器”，与triggers的事件触发不同，event类似与linux crontab计划任务，用于时间触发。通过单独或调用存储过程使用，在某一特定的时间点，触发相关的SQL语句或存储过程。

<!-- more -->
# 适用范围
对于每隔一段时间就有固定需求的操作，如创建表，删除数据等操作，可以使用event来处理。
例如：使用event在每月的1日凌晨1点自动创建下个月需要使用的三张表。

# 使用权限
单独使用event调用SQL语句时，查看和创建需要用户具有event权限，调用该SQL语句时，需要用户具有执行该SQL的权限。Event权限的设置保存在mysql.user表和mysql.db表的Event_priv字段中。 
# 配置Events自动启动

编辑/etc/my.cnf文件,mysql重启后,job能自动启动，在[mysqld]下添加event_scheduler=1
```
[root@node1 etc]# more my.cnf
[mysqld]
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
user=mysql
symbolic-links=0
#在[mysqld]下添加event_scheduler=1
event_scheduler=1
```