---
title: Supervisor的使用和配置
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
abbrlink: 2050126218
date: 2017-12-27 21:56:00
---
Supervisor是一个进程监控程序。
满足的需求是：我现在有一个进程需要每时每刻不断的跑，但是这个进程又有可能由于各种原因有可能中断。当进程中断的时候我希望能自动重新启动它，此时，我就需要使用到了Supervisor
<!-- more -->
# 先弄懂两个命令:
supervisord : supervisor的服务器端部分，启动supervisor就是运行这个命令
supervisorctl：启动supervisor的命令行窗口。
# 需求：
redis-server这个进程是运行redis的服务。我们要求这个服务能在意外停止后自动重启。

# 安装（Centos）：
```bash
yum install python-setuptools
easy_install supervisor
```
# 测试是否安装成功：
```bash
echo_supervisord_conf
```
# 创建配置文件：
```bash
echo_supervisord_conf > /etc/supervisord.conf
```
# 修改配置文件：
```
#在supervisord.conf最后增加：
[program:redis]
command = redis-server   //需要执行的命令
autostart=true    //supervisor启动的时候是否随着同时启动
autorestart=true   //当程序跑出exit的时候，这个program会自动重启
startsecs=3  //程序重启时候停留在runing状态的秒数
//（更多配置说明请参考：http://supervisord.org/configuration.html）
```
# 运行命令：
```
[root@vm14211 ~]# service supervisord start    //启动supervisor
[root@vm14211 ~]# supervisorctl   //打开命令行
redis                            RUNNING    pid 24068, uptime 3:41:55
supervisor> help   //查看命令
supervisor> status //查看状态
```
# 遇到的问题：
 1. redis出现的不是running而是FATAL 状态
应该要去查看log
log在/tmp/supervisord.log

 2. 日志中显示
    gave up: redis entered FATAL state, too many start retries too quickly
    修改redis.conf的daemonize为no

# 完成验证：
```bash
[root@vm1~]# ps aux | grep redis 
root     30582  0.0  0.0   9668  1584 ?        S    14:12   0:00 redis-server
[root@vm1~]# kill 30582
[root@vm1~]# ps aux | grep redis 
root     30846  0.0  0.0   9668  1552 ?        S    15:19   0:00 redis-server
//看到这个时候pid更新了。完成,庆祝。
```
-------------------------------------------------------------------
# Supervisor详细说明 ：
supervisor:C/S架构的进程控制系统，可使用户在类UNIX系统中监控、管理进程。常用于管理与某个用户或项目相关的进程。

## 组成部分
supervisord：服务守护进程
supervisorctl：命令行客户端
Web Server：提供与supervisorctl功能相当的WEB操作界面
XML-RPC Interface：XML-RPC接口
## 文件路径 
```
#日志
vim /var/log/supervisor/supervisord.log
#配置文件
vim /etc/supervisord.conf
```
## 配置样例
```bash
#[program:x]中配置要监控的进程

[supervisord]
http_port=/var/tmp/supervisor.sock ; (default is to run a UNIX domain socket server)
;http_port=127.0.0.1:9001  ; (alternately, ip_address:port specifies AF_INET)
;sockchmod=0700              ; AF_UNIX socketmode (AF_INET ignore, default 0700)
;sockchown=nobody.nogroup    ; AF_UNIX socket uid.gid owner (AF_INET ignores)
;umask=022                  ; (process file creation umask;default 022)
logfile=/var/log/supervisor/supervisord.log ; (main log file;default $CWD/supervisord.log)
logfile_maxbytes=50MB      ; (max main logfile bytes b4 rotation;default 50MB)
logfile_backups=10          ; (num of main logfile rotation backups;default 10)
loglevel=info              ; (logging level;default info; others: debug,warn)
pidfile=/var/run/supervisord.pid ; (supervisord pidfile;default supervisord.pid)
nodaemon=false              ; (start in foreground if true;default false)
minfds=1024                ; (min. avail startup file descriptors;default 1024)
minprocs=200                ; (min. avail process descriptors;default 200)
;nocleanup=true              ; (don't clean up tempfiles at start;default false)
;http_username=user          ; (default is no username (open system))
;http_password=123          ; (default is no password (open system))
;childlogdir=/tmp            ; ('AUTO' child log dir, default $TEMP)
;user=chrism                ; (default is current user, required if root)
;directory=/tmp              ; (default is not to cd during start)
;environment=KEY=value      ; (key value pairs to add to environment)
[supervisorctl]
serverurl=unix:///var/tmp/supervisor.sock ; use a unix:// URL  for a unix socket
;serverurl=http://127.0.0.1:9001 ; use an http:// url to specify an inet socket
;username=chris              ; should be same as http_username if set
;password=123                ; should be same as http_password if set
;prompt=mysupervisor        ; cmd line prompt (default "supervisor")
; The below sample program section shows all possible program subsection values,
; create one or more 'real' program: sections to be able to control them under
; supervisor.
;[program:example]
;command=/bin/echo; the program (relative uses PATH, can take args)
;priority=999                ; the relative start priority (default 999)
;autostart=true              ; start at supervisord start (default: true)
;autorestart=true            ; retstart at unexpected quit (default: true)
;startsecs=10                ; number of secs prog must stay running (def. 10)
;startretries=3              ; max # of serial start failures (default 3)
;exitcodes=0,2              ; 'expected' exit codes for process (default 0,2)
;stopsignal=QUIT            ; signal used to kill process (default TERM)
;stopwaitsecs=10            ; max num secs to wait before SIGKILL (default 10)
;user=chrism                ; setuid to this UNIX account to run the program
;log_stdout=true            ; if true, log program stdout (default true)
;log_stderr=true            ; if true, log program stderr (def false)
;logfile=/var/log/supervisor.log    ; child log path, use NONE for none; default AUTO
;logfile_maxbytes=1MB        ; max # logfile bytes b4 rotation (default 50MB)
;logfile_backups=10          ; # of logfile backups (default 10)
“;”为注释。各参数的含义都很明确。可以根据官方手册结合实验来进一步深入了解。重点说几个[program:example]中的参数
;command=/bin/echo;   supervisor启动时将要开启的进程。相对或绝对路径均可。若是相对路径则会从supervisord的$PATH变中查找。命令可带参数。
;priority=999                 指明进程启动和关闭的顺序。低优先级表明进程启动时较先启动关闭时较后关闭。高优先级表明进程启动时启动时较后启动关闭时较先关闭。
;autostart=true               是否随supervisord启动而启动
;autorestart=true             进程意外退出后是否自动重启
;startsecs=10                 进程持续运行多久才认为是启动成功
;startretries=3               重启失败的连续重试次数
;exitcodes=0,2               若autostart设置为unexpected且监控的进程并非因为supervisord停止而退出，那么如果进程的退出码不在exitcode列表中supervisord将重启进程
;stopsignal=QUIT             杀进程的信号
;stopwaitsecs=10             向进程发出stopsignal后等待OS向supervisord返回SIGCHILD 的时间。若超时则supervisord将使用SIGKILL杀进程
一个Rabbitmq项目中生产者和消费者进程使用supervisor监控的配置情况：(配置中的其他部分略)
[program:worker_for_summary]
command=/home/op1/scripts/rabbitmqclient/worker_for_summary.py
priority=1
log_stderr=true            ; if true, log program stderr (def false)
[program:worker_for_detail_all]
command=/home/op1/scripts/rabbitmqclient/worker_for_detail_all.py
priority=1
log_stderr=true            ; if true, log program stderr (def false)
[program:worker_for_detail_recent_list]
command=/home/op1/scripts/rabbitmqclient/worker_for_detail_recent_list.py
priority=1
log_stderr=true            ; if true, log program stderr (def false)
[program:worker_for_detail_recent_sset]
command=/home/op1/scripts/rabbitmqclient/worker_for_detail_recent_sset.py
priority=1
log_stderr=true            ; if true, log program stderr (def false)
[program:publisher_for_summary]
command=/home/op1/scripts/rabbitmqclient/publisher_for_summary.py
priority=999
log_stderr=true            ; if true, log program stderr (def false)
[program:publisher_for_summary_nt]
command=/home/op1/scripts/rabbitmqclient/publisher_for_summary_nt.py
priority=999
log_stderr=true            ; if true, log program stderr (def false)
[program:publisher_for_detail]
command=/home/op1/scripts/rabbitmqclient/publisher_for_detail.py
priority=999
log_stderr=true            ; if true, log program stderr (def false)
[program:publisher_for_detail_nt]
command=/home/op1/scripts/rabbitmqclient/publisher_for_detail_nt.py
priority=999
log_stderr=true            ; if true, log program stderr (def false)
```
## 查看帮助
```
supervisor> help
Documented commands (type help <topic>):
========================================
EOF    exit  maintail  quit    restart  start  stop
clear  help  open      reload  shutdown  status  tail
supervisor> help stop
stop <processname>   Stop a process.
stop <processname> <processname> Stop multiple processes
stop all    Stop all processes
  When all processes are stopped, they are stopped in
  reverse priority order (see config file)
supervisor> help status
status   Get all process status info.
status <name>  Get status on a single process by name.
status <name> <name> Get status on multiple named processes.
```
## 停止某个进程
```
supervisor> stop publisher_for_summary
publisher_for_summary: stopped
```
## 查看状态
```bash
supervisor> status
publisher_for_detail RUNNING    pid 27557, uptime 0:05:41
publisher_for_detail_nt RUNNING    pid 27567, uptime 0:05:41
publisher_for_summary STOPPED    Feb 27 02:48 PM
publisher_for_summary_nt RUNNING    pid 27568, uptime 0:05:41
worker_for_detail_all RUNNING    pid 27581, uptime 0:05:41
worker_for_detail_recent RUNNING    pid 27582, uptime 0:05:41
worker_for_summary RUNNING    pid 27559, uptime 0:05:41
```
## 开启停掉的进程
```bash
supervisor> start publisher_for_summary
publisher_for_summary: started
supervisor> status
publisher_for_detail RUNNING    pid 27557, uptime 0:08:02
publisher_for_detail_nt RUNNING    pid 27567, uptime 0:08:02
publisher_for_summary RUNNING    pid 3035, uptime 0:00:04
publisher_for_summary_nt RUNNING    pid 27568, uptime 0:08:02
worker_for_detail_all RUNNING    pid 27581, uptime 0:08:02
worker_for_detail_recent RUNNING    pid 27582, uptime 0:08:02
worker_for_summary RUNNING    pid 27559, uptime 0:08:02
```
## 停掉所有进程
```bash
supervisor> stop all
worker_for_detail_recent: stopped
worker_for_detail_all: stopped
publisher_for_summary_nt: stopped
publisher_for_detail_nt: stopped
publisher_for_summary: stopped
worker_for_summary: stopped
publisher_for_detail: stopped
supervisor> status
publisher_for_detail STOPPED    Feb 27 02:51 PM
publisher_for_detail_nt STOPPED    Feb 27 02:51 PM
publisher_for_summary STOPPED    Feb 27 02:51 PM
publisher_for_summary_nt STOPPED    Feb 27 02:51 PM
worker_for_detail_all STOPPED    Feb 27 02:51 PM
worker_for_detail_recent STOPPED    Feb 27 02:51 PM
worker_for_summary STOPPED    Feb 27 02:51 PM
```
## 开启所有进程
```bash
supervisor> start all
publisher_for_detail: started
worker_for_summary: started
publisher_for_summary: started
publisher_for_detail_nt: started
publisher_for_summary_nt: started
worker_for_detail_all: started
worker_for_detail_recent: started
```