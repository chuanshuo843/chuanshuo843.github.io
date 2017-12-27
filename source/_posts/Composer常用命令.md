title: Composer常用命令
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:35:00
---
Composer 是 PHP5以上 的一个依赖管理工具。它允许你申明项目所依赖的代码库，它会在你的项目中为你安装他们。Composer 不是一个包管理器。是的，它涉及 "packages" 和 "libraries"，但它在每个项目的基础上进行管理，在你项目的某个目录中（例如 vendor）进行安装。默认情况下它不会在全局安装任何东西。因此，这仅仅是一个依赖管理。
# 更换国内镜像源
```
composer config -g repo.packagist composer https://packagist.phpcomposer.com
```
# require命令
我们可以使用 require 命令快速的安装一个依赖而不需要手动在 composer.json 里添加依赖信息
```
composer require monolog/monolog
```
# update命令
通过 update 命令，可以更新项目里所有的包，或者指定的某些包。
```
# 更新所有依赖
$ composer update

# 更新指定的包
$ composer update monolog/monolog

# 更新指定的多个包
$ composer update monolog/monolog symfony/dependency-injection

# 还可以通过通配符匹配包
$ composer update monolog/monolog symfony/*
```
# remove命令
使用remove命令可以移除一个包及其依赖（在依赖没有被其他包使用的情况下）
```
composer remove monolog/monolog
```
# search命令
```
$ composer search monolog
monolog/monolog Sends your logs to files, sockets, inboxes, databases and various web services

# 如果只是想匹配名称可以使用--only-name选项
$ composer search --only-name monolog
```
# show命令
使用 show 命令可以列出项目目前所安装的包的信息
```
# 列出所有已经安装的包
$ composer show

# 可以通过通配符进行筛选
$ composer show monolog/*

# 显示具体某个包的信息
$ composer show monolog/monolog
```
# 版本约束
前面说到，我们可以指定要下载的包的版本。例如我们想要下载版本1.19的monolog。我们可以通过 composer.json 文件
```
$ composer require monolog/monolog:1.19

# 或者
$ composer require monolog/monolog=1.19

# 或者
$composer require monolog/monolog 1.19

//composer设置忽略版本匹配
$ composer install --ignore-platform-reqsor
$ composer update --ignore-platform-reqs  
```