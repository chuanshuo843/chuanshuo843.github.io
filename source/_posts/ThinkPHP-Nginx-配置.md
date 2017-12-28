title: ThinkPHP-Nginx-配置
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
date: 2017-12-28 20:58:00
---
```
server {
        listen       80;
        server_name  www.yii.com ;
        root   "E:/Code/caitongsheApp";
        index  index.html index.htm index.php;
        location  ~ \.php(.*)$ {
            fastcgi_pass   127.0.0.1:9000;
            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
            fastcgi_param  PATH_INFO  $fastcgi_path_info;
            fastcgi_param  PATH_TRANSLATED  $document_root$fastcgi_path_info;
            fastcgi_param  HTTPS              off;
        }
        location / {
            if (!-e $request_filename) {
                     rewrite ^(.*)$ /index.php?s=$1 last;
                 break;
            }
        } 
}
```
<!-- more -->