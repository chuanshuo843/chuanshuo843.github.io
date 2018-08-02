---
title: 基于Docker和Jenkins的CI改造
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
abbrlink: 4226450635
date: 2017-12-28 19:22:00
---
持续集成是一种软件开发实践，对于提高软件开发效率并保障软件开发质量提供了理论基础，旨在提供一个开放易用的软件平台，使持续集成变成可能。为了以后方便现在把博客迁移到了Docker上面,由于只有一台机器所以这里就没有使用Docker Registry了
<!-- more -->
# 介绍
## 原理图
{% asset_img d93a79d2143109794be84f309cf16f59.jpg 原理图 %}
## 目录结构
```bash
/root/work
.
├── config #blog配置文件存放处
│   └── app.conf 
├── data #blog数据存放处
│   ├── leanote #程序公共文件
│   │   ├── files
│   │   ├── mongodb_backup
│   │   └── upload
│   └── mongo #程序Nosql数据保存文件
├── Dockerfile #博客的Dockerfile，Jenkins基于他进行镜像构建
├── jenkins #Jenkins挂载目录
└── update #自动升级脚本
    └── update_blog_docker.sh #基于docker的升级脚本
```
# Docker
Docker 是一个开源的应用容器引擎，让开发者可以打包他们的应用以及依赖包到一个可移植的容器中，然后发布到任何流行的 Linux 机器上，也可以实现虚拟化。容器是完全使用沙箱机制，相互之间不会有任何接口。
## 安装Docker
```bash
yum install docker
```
## 启动服务
```bash
service docker start
```
# Jenkins
Jenkins是一个开源软件项目，旨在提供一个开放易用的软件平台，使软件的持续集成变成可能。
## 安装Jenkins
```
docker pull docker.io/jenkins
```
## 启动Jenkins的容器服务
```
docker run -d --name jenkins -p 127.0.0.1:8080:8080 -p 127.0.0.1:50000:50000 -v /root/jenkins:/var/jenkins_home jenkins
```
# Dockerfile
## 博客的基础镜像lenoate_env
由于使用的开发版本的leanote所以自己构建了一个golang的开发环境
```dockerfile
#系统
FROM golang:1.6 
#作者
MAINTAINER DuanEnJian "admin@ganktools.com"
#ENV GOROOT /usr/local/go
#ENV GOPATH /go
#ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN cd /go/src && wget http://golangtc.com/static/download/packages/golang.org.x.crypto.tar.gz && wget http://golangtc.com/static/download/packages/gopkg.in.mgo.v2.tar.gz && wget http://golangtc.com/static/download/packages/github.com.revel.cmd.tar.gz && wget http://golangtc.com/static/download/packages/golang.org.x.net.tar.gz && wget http://golangtc.com/static/download/packages/github.com.robfig.pathtree.tar.gz && wget http://golangtc.com/static/download/packages/github.com.revel.config.tar.gz && wget http://golangtc.com/static/download/packages/github.com.klauspost.crc32.tar.gz && wget http://golangtc.com/static/download/packages/github.com.klauspost.cpuid.tar.gz && wget http://golangtc.com/static/download/packages/github.com.klauspost.compress.tar.gz && wget http://golangtc.com/static/download/packages/github.com.agtorre.gocolorize.tar.gz && wget http://golangtc.com/static/download/packages/github.com.revel.revel.tar.gz && wget http://golangtc.com/static/download/packages/golang.org.x.sys.tar.gz && tar -zxvf golang.org.x.crypto.tar.gz && tar -zxvf golang.org.x.net.tar.gz && tar -zxvf github.com.robfig.pathtree.tar.gz && tar -zxvf github.com.revel.config.tar.gz && tar -zxvf github.com.klauspost.crc32.tar.gz && tar -zxvf github.com.klauspost.cpuid.tar.gz && tar -zxvf github.com.klauspost.compress.tar.gz && tar -zxvf github.com.agtorre.gocolorize.tar.gz && tar -zxvf github.com.revel.revel.tar.gz && tar -zxvf golang.org.x.sys.tar.gz && tar -zxvf github.com.revel.cmd.tar.gz && tar -zxvf gopkg.in.mgo.v2.tar.gz && go get github.com/revel/revel && go get github.com/revel/cmd/revel && go get gopkg.in/mgo.v2 && rm -rf golang.org.x.net.tar.gz github.com.robfig.pathtree.tar.gz github.com.revel.config.tar.gz github.com.klauspost.crc32.tar.gz github.com.klauspost.cpuid.tar.gz github.com.klauspost.compress.tar.gz github.com.agtorre.gocolorize.tar.gz github.com.revel.revel.tar.gz golang.org.x.sys.tar.gz github.com.revel.cmd.tar.gz gopkg.in.mgo.v2.tar.gz golang.org.x.crypto.tar.gz
```
## 博客的打包镜像
leanote自动构建的dockerfile
```dockerfile
FROM leanote_env
#作者
MAINTAINER DuanEnJian "admin@ganktools.com"
#拷贝博客文件
ADD blog.tar.gz /go/src/github.com/leanote/leanote/
#拷贝博客配置文件
COPY config/app.conf /go/src/github.com/leanote/leanote/conf/app.conf
#建立挂载目录软链接
RUN mkdir -p /leanote/data/upload/ \
    && mkdir -p /leanote/data/files/ \
    && mkdir -p /leanote/data/mongodb_backup/ \
    && ln -s /leanote/data/upload/ /go/src/github.com/leanote/leanote/public/ \
    && ln -s /leanote/data/files/ /go/src/github.com/leanote/leanote/ \
    && ln -s /leanote/data/mongodb_backup/ /go/src/github.com/leanote/leanote/
#挂载目录
VOLUME ["/leanote/data"]
#开放端口
EXPOSE 8081
#进入工作目录
WORKDIR /go/src
#执行命令
ENTRYPOINT revel run github.com/leanote/leanote prod 8081 && /bin/bash
```
# 自动升级脚本
update_blog_docker.sh
```bash
#!/bin/bash

#定义全局变量
WORK_DIR="/root/work"; #工作目录
NEW_IMAGE_NAME="leanote_"$(date +%Y%m%d%H%M%S); #镜像和容器名称
CURRENT_RUN_IMAGE_NAME=;

#构建镜像
function docker_build_image(){
    blog_file_path="/root/work/jenkins/workspace/Blog";
    #判断文件是否存在
    if [ ! -s ${blog_file_path} ]; then
        echo "[MSG]:blog source files not find !!";
        exit 1;
    fi;
    #打包压缩博客文件
    cd ${blog_file_path}
    tar -czvf blog.tar.gz *
    mv blog.tar.gz ${WORK_DIR}
    #进入工作目录
    cd ${WORK_DIR}
    #构建镜像
    docker build -t ${NEW_IMAGE_NAME} .
    if [ $? -eq 0 ]; then
        unlink blog.tar.gz
        echo "[MSG]:build images ${NEW_IMAGE_NAME} success!!";
        return 0;
    else
        echo "[MSG]:build image failed !!";
        exit 1;
    fi;
}

#停止当前运行的博客容器
function stop_run_blog_container(){
    #获取所有的博客容器
    current_run_container_name=$(docker ps -a |awk '{print $2}' |grep ^leanote_[0-9]*[0-9]);
    #判断是否存在博客容器
    if [ $current_run_container_name ]; then
        #判断博客容器是否在运行，停止运行的博客容器
        if [[ `docker ps | grep ${current_run_container_name}` ]]; then
            docker stop ${current_run_container_name} > /dev/null
        fi;
        #判断是否停止成功
        if [ $? -eq 0 ]; then
            echo "[MSG]:stop blog container ${current_run_container_name} success !!";
            CURRENT_RUN_IMAGE_NAME=${current_run_container_name};
            return 0;
        else
            echo "[MSG]:stop blog container ${current_run_container_name} failed !!";
            exit 1;
        fi;
    else
        #不存在博客的容器
        echo "[MSG]:stop run blog container success !!";
        return 0;
    fi
}

#删除旧的博客容器
function del_abandoned_container(){
    #判断是否存在博客容器，存在则删除容器
    if [ $CURRENT_RUN_IMAGE_NAME ]; then
        docker rm ${CURRENT_RUN_IMAGE_NAME} > /dev/null
        if [ $? -eq 0 ]; then
            echo "[MSG]:delete container ${CURRENT_RUN_IMAGE_NAME} success !!";
            return 0; 
        else
            echo "[MSG]:delete container ${CURRENT_RUN_IMAGE_NAME} failed !!";
            exit 1;
        fi;
    else
        #不存在跳过
        return 0;
    fi;
}

#运行新的博客镜像容器
function run_new_blog_container(){
    docker run -d --name ${NEW_IMAGE_NAME} -v /root/work/data/leanote:/leanote/data --link mongo:mongo_addr -p 127.0.0.1:8081:8081 ${NEW_IMAGE_NAME} /bin/bash > /dev/null
    if [ $? -eq 0 ]; then
        echo "[MSG]:start new blog container ${NEW_IMAGE_NAME} success !!";
        return 0;
    else
        echo "[MSG]:start new blog container ${NEW_IMAGE_NAME} failed !!";
        exit 1;
    fi;
}

#删除不要的镜像
function del_abandoned_image(){
    del_image_list=$(docker images |grep ^leanote_[0-9]*[0-9] | awk '{print $1}' | sort -r | awk 'NR >2{print}');
    if [ "${del_image_list}" != "" ]; then
        docker rmi ${del_image_list} > /dev/null
        if [ $? -eq 0 ]; then
            echo "[MSG]:del abandoned image ${del_image_list} success !!";
            return 0;
        else
            echo "[MSG]:del abandoned image ${del_image_list} failed !!";
            exit 1;
        fi;
    else
        echo "[MSG]:delete abandoned image success !!";
        return 0;
    fi;
}

#脚本开始
function start(){
    #构建镜像
	docker_build_image;
    #停止当前博客容器
    stop_run_blog_container;
    #删除当前容器
    del_abandoned_container;
    #运行新的博客镜像容器
    run_new_blog_container;
    #删除作废的镜像
    del_abandoned_image;
    #检测新的博客镜像容器是否正常运行
    docker ps 
    new_run_container_name=$(docker ps |awk '{print $2}' |grep ^leanote_[0-9]*[0-9]);
    if [ $new_run_container_name ]; then
        #博客升级完成
        echo "[MSG]:update blog container success !!";
        #更新完成退出
        exit 0;
    else
        #博客升级失败
        echo "[MSG]:update blog container failed !!";
        exit 1;
    fi;
}

start;
```
# nginx配置
```nginx
    # 这里是blog的http解析配置
    server
    {
        listen  80 default_server;
        server_name  www.ganktools.com;
        # 强制https
        # 如果不需要, 请注释这一行rewrite
        #rewrite ^/(.*) https://www.ganktools.com/$1 permanent;
        location / {
            proxy_pass         http://127.0.0.1:8081;
            proxy_set_header   Host             $host;
            proxy_set_header   X-Real-IP        $remote_addr;
            proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        }
    }

    # 这里是blog的htts解析配置
    server
    {
        listen  443 ssl;
        server_name  www.ganktools.com;
        ssl_certificate     /opt/ssl_key/ganktools.com.crt; # 修改路径, 到a.com.crt, 下同
        ssl_certificate_key /opt/ssl_key/ganktools.com.key;
        location / {
            proxy_pass         http://127.0.0.1:8081;
            proxy_set_header   Host             $host;
            proxy_set_header   X-Real-IP        $remote_addr;
            proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        }
    }
    #这里是jenkins域名解析的配置
    server
    {
        listen  80;
        server_name  ci.ganktools.com;
        location / {
            proxy_pass         http://127.0.0.1:8080;
            proxy_set_header   Host             $host;
            proxy_set_header   X-Real-IP        $remote_addr;
            proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        }
    }
```
# 配置Jenkins
Jenkins需要安装插件Git plugin,SSH plugin
## 系统配置
{% asset_img a0257d0410ca2a5488652db607ea75e1.png 系统配置 %}
## 项目配置
{% asset_img 74c9c61306b27cd1d2ec4a9d547595eb.png 项目配置 %}
## GitHub-Api的Token获取
{% asset_img 454b1bce8908652134b22a01e8e2ddf8.png GitHub-Api的Token获取 %}
## 参考资料
[Jenkins+Github持续集成](https://segmentfault.com/a/1190000004640060)
[jenkins + Git 搭建持续集成环境](http://www.cnblogs.com/dojo-lzz/p/5125619.html)