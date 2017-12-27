title: PHP的适配器模式实现
author: DuanEnJian
tags:
  - PHP
  - 设计模式
categories:
  - 开发
date: 2017-12-27 20:57:00
---
适配器模式在不修改现有代码的基础上，保留了架构。使用继承的适配器和使用组件的适配器各有利弊，继承的类冗余度/空间复杂度偏高，组件的调用栈/时间复杂度偏高，应该结合实际情况选择。

# 概念
- 简单来说，当你的实现和需要的接口，都无法修改的时候。

- 例如，你需要给甲方已有的系统做标准的兼容，标准不可修改，甲方的系统也不可修改，这个时候你就需要适配器的设计模式了。

- 对于web编程来说，将你现有的实现，和三方库结合起来，就需要使用适配器模式。

- 适配器模式是一种利用适配器将现有的实现，适配到已有接口的设计模式，最常见的例子就是变压器，将已有的5V输入的电器，通过变压器，适配到220V的电源插座。

- **相比继承，组件可用性高，低耦合，冗余度低，因此推荐采用组件的模式来进行设计。**

# 继承方式实现
```php
<?php

//目标角色
interface ITarget
{
    function operation1();
    function operation2();
}

//源角色
interface IAdaptee
{
    function operation1();
}

class Adaptee implements IAdaptee
{
    public  function operation1()
    {
        echo "原方法";
    }
}

//类适配器角色
class Adapter extends Adaptee implements ITarget
{
    public function operation2()
    {
        echo "适配方法";
    }
}

//客户端
class Client
{
    public  function test()
    {
        $adapter = new Adapter();
        $adapter->operation1();//原方法
        $adapter->operation2();//适配方法
    }
}
```
# 组件方式实现
```php
<?php

//目标角色
interface ITarget
{
    function operation1();
    function operation2();
}

//源角色
interface IAdaptee
{
    function operation1();
}

class Adaptee implements IAdaptee
{
    public  function operation1()
    {
        echo "原方法";
    }
}

//适配器类
class Adapter implements  ITarget
{
    private $adaptee;

    public function __construct($adaptee)
    {
        $this->adaptee = $adaptee;
    }

    public  function operation1()
    {
        return $this->adaptee->operation1();
    }

    public  function operation2()
    {
        echo "适配方法";
    }
}

//客户端
class Client
{
    public  function test()
    {
        $adapter = new Adapter(new Adaptee());
        $adapter->operation1();//原方法
        $adapter->operation2();//适配方法
    }
}
```