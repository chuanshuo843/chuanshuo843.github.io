title: Linux安装ODBC_MYSQL连接
author: DuanEnJian
tags:
  - MySQL
  - Linux
categories:
  - 运维
date: 2017-12-27 21:41:00
---
ODBC连接器是一个数据库抽象层，它可以让Asterisk与广泛 的数据库进行通信，而无需开发人员为Asterisk需要的每一个数据库创建一个单独的数据库连接。这样可以节省大量的开发工作和代码维护。因为我们在 Asterisk和数据库之间添加了其他应用层可能会有轻微的性能损失，但当你需要Asterisk系统功能强大，灵活的数据库功能时可以缓解适当的设计 是值得的。
# 安装
在安装连接器在Asterisk前，您必须安装ODBC到Linux上。要安装的ODBC驱动程序，请使用以下命令。
```
$ sudo yum install unixODBC unixODBC-devel libtool-ltdl libtool-ltdl-devel
```
默认情况下，CentOS会安装通过ODBC连接PostgreSQL的驱动。要安装ODBC连接MySQL的驱动请执行下面的指令。
```
$ sudo yum install mysql-connector-odbc
```
# 为MySQL配置ODBC
MySQL的配置文件在/etc/odbcinst.ini
```
#CentOS上默认文件已经包含了一些数据，包括MySQL的也存在，但我们需要一些更改。用下面的数据进行更改。
[MySQL]
Description = ODBC for MySQL
Driver = /usr/lib/libmyodbc3.so
Setup = /usr/lib/libodbcmyS.so
FileUsage = 1
```
通过运行下面的指令验证系统能找到驱动，如果一切都OK，会返回MySQL的标题。
```
$ odbcinst -q -d
```
接下来，配置/etc/odbc.ini文件，根据自己的需要配置这里的文件，使数据库能被你的软件使用
```
[MySQL]
[asterisk-connector]
Description           = MySQL connection to 'asterisk' database
Driver                = MySQL
Database              = asterisk
Server                = localhost
UserName              = asterisk
Password              = welcome
Port                  = 3306
Socket                = /var/lib/mysql/mysql.sock
```
# 验证ODBC连接器
现在利用isql功能验证能连到你的数据库上，当你输入指令后会看到结果为1的返回值就表明连接成功了
```
$ echo "select 1" | isql -v asterisk-connector
+---------------------------------------+
| Connected!                            |
|                                       |
| sql-statement                         |
| help [tablename]                      |
| quit                                  |
|                                       |
+---------------------------------------+
SQL> 
+------------+
| ?column?   |
+------------+
| 1          |
+------------+
SQLRowCount returns 1
1 rows fetched
$ exit
```
到这里就达到我要连接MySQL的目的了。