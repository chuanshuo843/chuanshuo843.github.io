title: PHP之spl_autoload_register使用说明
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
  - ''
date: 2017-12-27 19:41:00
---
spl_autoload_register — 注册给定的函数作为 __autoload 的实现
将函数注册到SPL __autoload函数队列中。如果该队列中的函数尚未激活，则激活它们。
如果在你的程序中已经实现了__autoload()函数，它必须显式注册到__autoload()队列中。因为spl_autoload_register()函数会将Zend Engine中的__autoload()函数取代为spl_autoload()或spl_autoload_call()。

如果需要多条 autoload 函数，spl_autoload_register() 满足了此类需求。 它实际上创建了 autoload 函数的队列，按定义时的顺序逐个执行。相比之下， __autoload() 只可以定义一次。
**(PHP 5 >= 5.1.2, PHP 7)**

<!-- more -->

# 核心实代码
```php
<?php
 
class autoload 
{ 
  public static function load( $class name ) 
  {
    $filename = "/home/user/class/".$classname."class.php";
    if (file_exists($filename )) { 
      require_once $filename ; 
    } 
  } 
} 
 
function __autoload( $class name )
{ // 这个是默认的 autoload 方法
    $filename = "/home/user/class/".$classname."class.php";
    if (file_exists($filename )) { 
      require_once $filename ; 
  } 
} 
 
// 注册一个 autoloader 
spl_autoload_register( 'autoload::load' ); 
/** 
* __autoload 方法在 spl_autoload_register 后会失效，因为 autoload_func 函数指针已指向 spl_autoload 方法 
* 可以通过下面的方法来把 _autoload 方法加入 autoload_functions list 
*/ 
spl_autoload_register( '__autoload' ); 
 // 注：下面的类看上去没有定义，但其实系统根据sql_autoload_register提供的路径会自动去/home/user// /class/*.class.php下搜索foo.class.php文件，如果没找到才报错。 
$foo = new foo(); 
$foo ->bar(); 
?>
```