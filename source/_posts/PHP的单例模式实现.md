title: PHP的单例模式实现
author: DuanEnJian
tags:
  - PHP
  - 设计模式
categories:
  - 开发
date: 2017-12-27 20:43:00
---
单例模式一般使用在资源共享和需要控制资源的情况下。

# 概念
单例模式的好处就在于当前进程只产生一个对象（或者叫做模块），
但有一点需要指出，如果单例模式的操作对象是一个资源类型，那么此时的单例模式并不是纯粹的单例模式，因为php的生命周期仅仅是页面级别的，所以他无法像Java语言那样在内存中将这个资源类型存起来，并且我们也无法借助类似redis的nosql缓存数据库，因为资源类型（类似mysql_connect的返回值）是无法被序列化（指的是资源无法转成字符串）。

即，php的单例,仅指进程中单例,不似java,在整个内存中单例，所以在PHP语言下，单例模式是有瑕疵的。

<!-- more -->

# 实现代码
通过输出（output）可以看出页面执行中，数据库类（class Database）只有第一次调用的时候是真实实例化的，剩下的调用都是直接从静态变量获取该实例的，这样的话就防止了在一次生命周期中多次连接数据库了，极大的节省了资源，这就是单例模式。

```php
<?php
    class Database {
    
        //数据库连接资源
        protected static $_db;
     
        //单例标识符
        protected static $_instance;
     
        //设可见性设置成private，防止外部进行 实例化操作
        private function __construct(){
     
        }
     
        //外部调用的是 getInstance
        public static function getInstance(){
     
            if (self :: $_instance === null) {
                self::$_instance = new self();
                self::$_db = mysql_connect('localhost','root','root');
                echo '只有一次实例化';
            }
            return self::$_instance;
        }
     
        public function select_db($db){
     
            return mysql_select_db($db,self::$_db);
     
        }
     
        //设可见性设置成private，防止外部进行 clone操作
        private function __clone(){
     
        }
    }
     
    $db = Database::getInstance();
    print_r($db->select_db('test'));
    print_r($db->select_db('test'));
    print_r($db->select_db('test'));
    //output:只有一次实例化111
     
?>
```