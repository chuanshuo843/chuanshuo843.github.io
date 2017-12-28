title: PHP把 session存到memcache中
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:53:00
---
企业网站用户数越来越多,同时在线人数越来越多,最大同时在线达100万之多,由于session文件是小文件存储,设想每个用户大概2K左右数据,NFS频繁读取导致IO成为瓶颈,虽然可以更改配置以分级目录的形式保持session但还是没有达到最优设计,但如果把session放在内存中,内存存取快速,就再也不用担心海量用户的压力了!

<!-- more -->
```php
<?php
    class MemSession {
        private static $handler=null;
        private static $lifetime=null;
        /**
         * 初使化和开启session
         * @param    Memcache    $memcache    memcache对象
         */
        public static function start(Memcache $memcache){
             //将 session.save_handler 设置为 user，而不是默认的 files
             //session文件保存方式，这个是必须的！除非在Php.ini文件中设置了
            ini_set('session.save_handler', 'user'); //等价于 session_module_name('user');
            self::$handler=$memcache;
            self::$lifetime=ini_get('session.gc_maxlifetime');
            session_set_save_handler(
                    array(__CLASS__, 'open'),
                    array(__CLASS__, 'close'),
                    array(__CLASS__, 'read'),
                    array(__CLASS__, 'write'),
                    array(__CLASS__, 'destroy'),
                    array(__CLASS__, 'gc')
                );
            session_start();
            return true;
        }
        public static function open($path, $name){
            return true;
        } 
        public static function close(){
            return true;
        }
        /**
         * 从SESSION中读取数据
         * @param    string    $PHPSESSID    session的ID
         * @return     mixed            返回session中对应的数据
         */
        public static function read($PHPSESSID){
            $out=self::$handler->get(self::session_key($PHPSESSID));
            if($out===false || $out == null)
                return '';
            return $out;
        }
        /**
         *向session中添加数据
         */
        public static function write($PHPSESSID, $data){
            $method=$data ? 'set' : 'replace';
            return self::$handler->$method(self::session_key($PHPSESSID), $data, MEMCACHE_COMPRESSED, self::$lifetime);
        }
        public static function destroy($PHPSESSID){
            return self::$handler->delete(self::session_key($PHPSESSID));
        }
        public static function gc($lifetime){
            //无需额外回收,memcache有自己的过期回收机制
            return true;
        }
        private static function session_key($PHPSESSID){
            $session_key=TABPREFIX.$PHPSESSID;
            return $session_key;
        }    
    }
    //使用
    $mem=new Memcache();
    $mem->connect('127.0.0.1', '11211');
    MemSession::start($mem);
    $_SESSION['myBlog']='http://www.ganktools.com';
```