title: PHP的ArrayAccess接口使用
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:29:00
---
PHP5 中多了一系列新接口。同时这些接口和一些实现的 Class 被归为 Standard PHP Library(SPL)。在 PHP5 中加入了很多特性，使类的重载 (Overloading) 得到进一步的加强。ArrayAccess 的作用是使你的 Class 看起来像一个数组(PHP 的数组)。这点和 C# 的 Index 特性很相似。
 
如果想让对象使用起来像一个PHP数组，那么我们需要实现ArrayAccess接口

ArrayAccess是一个interface，实现这个interface，必须要实现几个方法
# 示例代码
```php
class Test implements ArrayAccess {
    private $elements;
    public function offsetExists($offset){
        return isset($this->elements[$offset]);
    }
    public function offsetSet($offset, $value){
        $this->elements[$offset] = $value;
    }
    public function offsetGet($offset){
        return $this->elements[$offset];
    }
    public function offsetUnset($offset){
        unset($this->elements[$offset]);
    }
}
```
# 调用方式
```php
$test = new Test();
$test['test'] = 'test';//自动调用offsetSet
if(isset($test['test']))//自动调用offsetExists
{
    echo $test['test'];//自动调用offsetGet
    echo '<br />';
    unset($test['test']);//自动调用offsetUnset
    var_dump($test['test']);
}
//运行输出：
//test
//NULL 
```