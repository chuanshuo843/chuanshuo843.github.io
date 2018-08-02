---
title: nginx-lua-redis-反向代理
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
abbrlink: 2989278071
date: 2017-12-28 20:56:00
---
```
user  root;
worker_processes  8;
error_log  logs/error.log;
error_log  logs/error.log  notice;
error_log   logs/debug.log  debug;

#pid        logs/nginx.pid;

events {
    use epoll;
    worker_connections  1024;
}


http {
    include       mime.types;
    #default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;

    keepalive_timeout  30;
    send_timeout        30;

    client_header_buffer_size   8k;
    client_max_body_size        30M;
    large_client_header_buffers 4 4k;
    ignore_invalid_headers      off;
    
    lua_package_path "/usr/local/nginx/lualib/?.lua;;";
    lua_package_cpath "/usr/local/nginx/lualib/?.so;;";
    server {
        listen       80;
        location /{
			set $go_pkq '';
			access_by_lua '
				local redis = require "resty.redis"
                local red = redis:new()

                red:set_timeout(1000) -- 1 sec

                local ok, err = red:connect("172.17.0.6", 6379)
                if not ok then
                    --ngx.say("failed to connect: ", err)
                    return ""
                end

                local res, err = red:get(ngx.req.get_headers()["Host"])
                if not res then
                    --ngx.say("failed to get dog: ", err)
                    return ""
                end
				
				ngx.var.go_pkq = res
			';
			
            proxy_pass $scheme://$go_pkq$request_uri;
            proxy_set_header Host $http_host;            
            proxy_set_header Referer $http_referer;           
        }
    }
}
```
<!-- more -->