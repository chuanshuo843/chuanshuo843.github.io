---
title: Crontab定时任务设置
categories:
  - 运维
  - ''
tags:
  - Linux
author: DuanEnJian
abbrlink: 123452189
date: 2017-12-27 16:49:00
---
```
[root@localhost ~]# /sbin/service crond start
正在启动 crond：                                           [确定]
[root@localhost ~]# crontab -l
#每五分钟更新一次
*/5 * * * * curl "www.xxxx.com?update_cache.html"
*/5 * * * * curl "www.xxxx.com?update_cache.html"
*/5 * * * * curl "www.xxxx.com?update_cache.html"
#每天晚上23:59更新一次
59 23 * * * curl "www.xxxx.com?update_cache.html"
#每年1月1号23:59分执行
59 23 1 1 * curl "www.xxxx.com?update_cache.html"
查看定时器执行状态
tail -f /var/log/cron
```

<!-- more -->