title: PHP的类型约束
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:51:00
---
众所周知，在 强类型 语言中，类型约束 是语法上的要求，即：定义一个变量的时候，必须指定其类型，并且以后该变量也只能存储该类型数据。

而我们的PHP是弱类型语言，其特点就是无需为变量指定类型，而且在其后也可以存储任何类型，当然这也是使用PHP能快速开发的关键点之一。但是在php的高版本语法中（PHP5起），在某些特定场合，针对某些特定类型，也是可以进行语法约束的。

<!-- more -->
# 说明
自PHP5起，我们就可以在函数（方法）形参中使用类型约束了。

函数的参数可以指定的范围如下：

 - 必须为对象（在函数原型里面指定类的名字）；
 - 接口；
 - 数组（PHP 5.1 起）；
 - callable（PHP 5.4 起）。

如果使用 NULL 作为参数的默认值，那么在调用函数的时候依然可以使用 NULL 作为实参。
如果一个类或接口指定了类型约束，则其所有的子类或实现也都如此。

类型约束不能用于标量类型如 int 或 string。Traits 也不允许。

# 使用
```php
<?php
//如下面的类
class MyClass
{
    /**
     * 测试函数
     * 第一个参数必须为 OtherClass 类的一个对象
     */
    public function test(OtherClass $otherclass) {
        echo $otherclass->var;
    }


    /**
     * 另一个测试函数
     * 第一个参数必须为数组 
     */
    public function test_array(array $input_array) {
        print_r($input_array);
    }
}

    /**
     * 第一个参数必须为递归类型
     */
    public function test_interface(Traversable $iterator) {
        echo get_class($iterator);
    }
    
    /**
     * 第一个参数必须为回调类型
     */
    public function test_callable(callable $callback, $data) {
        call_user_func($callback, $data);
    }
}

// OtherClass 类定义
class OtherClass {
    public $var = 'Hello World';
}
?>
```
函数调用的参数与定义的参数类型不一致时，会抛出一个可捕获的致命错误。
```php
<?php
// 两个类的对象
$myclass = new MyClass;
$otherclass = new OtherClass;

// 致命错误：第一个参数必须是 OtherClass 类的一个对象
$myclass->test('hello');

// 致命错误：第一个参数必须为 OtherClass 类的一个实例
$foo = new stdClass;
$myclass->test($foo);

// 致命错误：第一个参数不能为 null
$myclass->test(null);

// 正确：输出 Hello World 
$myclass->test($otherclass);

// 致命错误：第一个参数必须为数组
$myclass->test_array('a string');

// 正确：输出数组
$myclass->test_array(array('a', 'b', 'c'));

// 正确：输出 ArrayObject
$myclass->test_interface(new ArrayObject(array()));

// 正确：输出 int(1)
$myclass->test_callable('var_dump', 1);
?>
```
类型约束不只是用在类的成员函数里，也能使用在函数里
```php
<?php
// 如下面的类
class MyClass {
    public $var = 'Hello World';
}

/**
 * 测试函数
 * 第一个参数必须是 MyClass 类的一个对象
 */
function MyFunction (MyClass $foo) {
    echo $foo->var;
}

// 正确
$myclass = new MyClass;
MyFunction($myclass);
?>
```
类型约束允许 NULL 值
```php
<?php

/* 接受 NULL 值 */
function test(stdClass $obj = NULL) {

}

test(NULL);
test(new stdClass);

?>
```
# 总结
以上就是PHP类型约束的大概简介和使用方法了，在使用PHP进行开发过程中，用到它的地方可能不是太多，我们最常看见或用到类型约束的地方是在“依赖注入”的设计模式中