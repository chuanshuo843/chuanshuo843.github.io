---
title: Mysql的主从配置实现
author: DuanEnJian
tags:
  - MySQL
categories:
  - 数据库
abbrlink: 3259372363
date: 2017-12-27 21:11:00
---
mysql内建的复制功能是构建大型，高性能应用程序的基础。将Mysql的数据分布到多个系统上去，这种分布的机制，是通过将Mysql的某一台主机的数据复制到其它主机（slaves）上，并重新执行一遍来实现的。复制过程中一个服务器充当主服务器，而一个或多个其它服务器充当从服务器。主服务器将更新写入二进制日志文件，并维护文件的一个索引以跟踪日志循环。这些日志可以记录发送到从服务器的更新。当一个从服务器连接主服务器时，它通知主服务器从服务器在日志中读取的最后一次成功更新的位置。从服务器接收从那时起发生的任何更新，然后封锁并等待主服务器通知新的更新。

<span style="color:red;" >**PS:当你进行复制时，所有对复制中的表的更新必须在主服务器上进行。否则，你必须要小心，以避免用户对主服务器上的表进行的更新与对从服务器上的表所进行的更新之间的冲突。**</span>

<!-- more -->

# Mysql复制类型

 - 基于语句的复制
 >在主服务器上执行的SQL语句，在从服务器上执行同样的语句。MySQL默认采用基于语句的复制，效率比较高。一旦发现没法精确复制时，   会自动选着基于行的复制。   

 - 基于行的复制
 >把改变的内容复制过去，而不是把命令在从服务器上执行一遍. 从mysql5.0开始支持

 - 混合类型的复制
 >默认采用基于语句的复制，一旦发现基于语句的无法精确的复制时，就会采用基于行的复制。

# 可以解决的问题
 - 数据分布 (Data distribution )
 - 负载平衡(load balancing)
 - 备份(Backups) 
 - 高可用性和容错行 High availability and failover 

# Mysql主从配置说明

ps: 1.注意防火墙,这里直接关闭 systemctl stop firewalld.service

ps: 2.注意mysql的sql_model,这里去掉STRICT_TRANS_TABLES
## 安装Mysql
```bash
wget http://dev.mysql.com/get/mysql-community-release-el7-5.noarch.rpm
rpm -ivh mysql-community-release-el7-5.noarch.rpm
yum install mysql-community-server
```
## Master配置
### 创建数据库
```sql
mysql> create database db_1;
mysql> create database db_2;
```
### 创建用户
```sql
mysql> insert into mysql.user(Host,User,Password) values('localhost','user_1',password('123456'));
flush privileges; 
```
### 用户授权
```sql
#授权用户user_1只能从172.23.150.82这个IP访问主服务器172.23.151.43上面的数据库，并且只具有数据库备份的权限
mysql> grant replication slave  on *.* to 'user_1'@'172.23.150.82' identified by '123456' with grant option; 
```
### 修改my.cnf
```bash
vim /etc/my.cnf
#设置服务器id，为1表示主服务器。
server-id=1  
 #启动MySQ二进制日志系统。
log_bin=mysql-bin 
#需要同步的数据库名，如果有多个数据库，每个数据库一行
binlog-do-db=db_1  
binlog-do-db=db_2  
#不同步mysql系统数据库
binlog-ignore-db=mysql   
```
### 查看主服务器
```sql
mysql> show master status;
+------------------+----------+--------------+------------------+-------------------+
| File             | Position | Binlog_Do_DB | Binlog_Ignore_DB | Executed_Gtid_Set |
+------------------+----------+--------------+------------------+-------------------+
| mysql-bin.000002 |      252 | k8s,k9s      | mysql            |                   |
+------------------+----------+--------------+------------------+-------------------+
1 row in set (0.00 sec)
#记住File，Position稍后使用
```
## Slave配置
MySQL 5.1.7版本之后，已经不支持把master配置属性写入my.cnf配置文件中了，只需要把同步的数据库和要忽略的数据库写入即可。
### 修改my.cnf
```bash
vim /etc/my.cnf
#设置服务器id。
server-id=2  
 #启动MySQ二进制日志系统。
log_bin=mysql-bin 
#需要同步的数据库名，如果有多个数据库，每个数据库一行
replicate-do-db=db_1  
replicate-do-db=db_2  
#不同步mysql系统数据库
replicate-ignore-db=mysql   
```
### 写入Master信息
```sql
#停止slave同步进程
mysql> stop slave; 
#同步信息
mysql> change master to master_host='172.23.151.43',master_user='user_1',master_password='123456',master_log_file='mysql-bin.000002' ,master_log_pos=252; 
#开启slave同步进程
mysql> start slave;    
```
### 查看slave信息
```sql
mysql> show slave status \G;
*************************** 1. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: 172.23.151.43
                  Master_User: user_1
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: mysql-bin.000002
          Read_Master_Log_Pos: 252
               Relay_Log_File: mysqld-relay-bin.000005
                Relay_Log_Pos: 415
        Relay_Master_Log_File: mysql-bin.000002
             Slave_IO_Running: Yes
            Slave_SQL_Running: Yes
              Replicate_Do_DB: k8s,k9s
          Replicate_Ignore_DB: mysql
           Replicate_Do_Table: 
       Replicate_Ignore_Table: 
      Replicate_Wild_Do_Table: 
  Replicate_Wild_Ignore_Table: 
                   Last_Errno: 0
                   Last_Error: 
                 Skip_Counter: 0
          Exec_Master_Log_Pos: 252
              Relay_Log_Space: 752
              Until_Condition: None
               Until_Log_File: 
                Until_Log_Pos: 0
           Master_SSL_Allowed: No
           Master_SSL_CA_File: 
           Master_SSL_CA_Path: 
              Master_SSL_Cert: 
            Master_SSL_Cipher: 
               Master_SSL_Key: 
        Seconds_Behind_Master: 0
Master_SSL_Verify_Server_Cert: No
                Last_IO_Errno: 0
                Last_IO_Error: 
               Last_SQL_Errno: 0
               Last_SQL_Error: 
  Replicate_Ignore_Server_Ids: 
             Master_Server_Id: 1
                  Master_UUID: c5836ee2-9a81-11e6-825f-080027d8142b
             Master_Info_File: /var/lib/mysql/master.info
                    SQL_Delay: 0
          SQL_Remaining_Delay: NULL
      Slave_SQL_Running_State: Slave has read all relay log; waiting for the slave I/O thread to update it
           Master_Retry_Count: 86400
                  Master_Bind: 
      Last_IO_Error_Timestamp: 
     Last_SQL_Error_Timestamp: 
               Master_SSL_Crl: 
           Master_SSL_Crlpath: 
           Retrieved_Gtid_Set: 
            Executed_Gtid_Set: 
                Auto_Position: 0
1 row in set (0.00 sec)
```
PS:

 - 成功
>Slave_IO_Running: Yes
Slave_SQL_Running: Yes
以上这两个参数的值为Yes，即说明配置成功！

 - 错误信息
>使用show slave status;查看Last_IO_Errno,Last_IO_Error来查看错误信息

 - 排查
>使用show variables like 'server_id';来检查server_id,server_id要不一样

# 参考资料
[高性能Mysql主从架构的复制原理及配置详解](http://blog.csdn.net/hguisu/article/details/7325124/)
[mysql的sql_mode合理设置](http://blog.csdn.net/wyzxg/article/details/8787878)
[MySQL主从复制结构中常用参数](http://blog.csdn.net/lanonola/article/details/52571651)