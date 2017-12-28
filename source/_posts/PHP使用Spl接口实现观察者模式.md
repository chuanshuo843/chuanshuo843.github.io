title: PHP使用Spl接口实现观察者模式
author: DuanEnJian
tags:
  - PHP
  - 设计模式
  - SPL标准库
categories:
  - 开发
date: 2017-12-27 20:04:00
---
SPL（Standard PHP Library）即标准 PHP 库，是 PHP 5 在面向对象上能力提升的真实写照，它由一系列内置的类、接口和函数构成。SPL 通过加入集合，迭代器，新的异常类型，文件和数据处理类等提升了 PHP 语言的生产力。它还提供了一些十分有用的特性，如本文要介绍的内置 Observer 设计模式。
本文介绍如何通过使用 SPL 提供的 SplSubject和 SplObserver接口以及 SplObjectStorage类，快速实现 Observer 设计模式。

观察者模式这是一种较为容易去理解的一种模式吧，它是一种事件系统，意味着这一模式允许某个类观察另一个类的状态，当被观察的类状态发生改变的时候，观察类可以收到通知并且做出相应的动作。比如键盘，我一敲击，系统就收到通知并进行相应的回应。

<!-- more -->
# 接口介绍
```php
<?php

interface SplSubject{
    public function attach(SplObserver $observer);//添加（注册）一个观察者
    public function detach(SplObserver $observer);//删除一个观察者
    public function notify();//当状态发生改变时，通知所有观察者
}

interface SplObserver{ 
    public function update(SplSubject $subject);//在目标发生改变时接收目标发送的通知；当关注的目标调用其 notify()时被调用
}
```
# 核心代码1
为什么使用 SplObjectStorage 类SplObjectStorage类实现了以对象为键的映射（map）或对象的集合（如果忽略作为键的对象所对应的数据）这种数据结构。这个类的实例很像一个数组，但是它所存放的对象都是唯一的。这个特点就为快速实现 Observer 设计模式贡献了不少力量，因为我们不希望同一个观察者被注册多次。该类的另一个特点是，可以直接从中删除指定的对象，而不需要遍历或搜索整个集合。

SplObjectStorage类的实例之所以能够只存储唯一的对象，是因为其 SplObjectStorage::attach()方法的实现中先判断了指定的对象是否已经被存储

```php
<?php 
 class User implements SplSubject { 
    private $email; 
    private $username; 
    private $mobile; 
    private $password; 
    /** 
     * @var SplObjectStorage 
     */ 
    private $observers = NULL; 

    public function __construct($email, $username, $mobile, $password) { 
        $this->email = $email; 
        $this->username = $username; 
        $this->mobile = $mobile; 
        $this->password = $password; 

        $this->observers = new SplObjectStorage(); 
    } 

    public function attach(SplObserver $observer) { 
        $this->observers->attach($observer); 
    } 

    public function detach(SplObserver $observer) { 
        $this->observers->detach($observer);
    } 

    public function notify() { 
        $userInfo = array( 
            'username' => $this->username, 
            'password' => $this->password, 
            'email' => $this->email, 
            'mobile' => $this->mobile, 
        ); 
        foreach ($this->observers as $observer) { 
            $observer->update($this, $userInfo); 
        } 
    } 

    public function create() { 
        echo __METHOD__, PHP_EOL; 
        $this->notify(); 
    } 

    public function changePassword($newPassword) { 
        echo __METHOD__, PHP_EOL; 
        $this->password = $newPassword; 
        $this->notify(); 
    } 

    public function resetPassword() { 
        echo __METHOD__, PHP_EOL; 
        $this->password = mt_rand(100000, 999999); 
        $this->notify(); 
    } 

 }
```
# 核心代码2
```php
<?php 
 class EmailSender implements SplObserver { 

    public function update(SplSubject $subject) { 
        if (func_num_args() === 2) { 
            $userInfo = func_get_arg(1); 
            echo "向 {$userInfo['email']} 发送电子邮件成功。内容是：你好 {$userInfo['username']}" . 
            "你的新密码是 {$userInfo['password']}，请妥善保管", PHP_EOL; 
        } 
    } 

 }
```
# 测试脚本
```php
<?php 
 header('Content-Type: text/plain'); 

 function __autoload($class_name) { 
    require_once "$class_name.php"; 
 } 

 $email_sender = new EmailSender(); 
 $mobile_sender = new MobileSender(); 
 $web_sender = new WebsiteSender(); 

 $user = new User('user1@domain.com', '张三', '13610002000', '123456'); 

 // 创建用户时通过 Email 和手机短信通知用户
 $user->attach($email_sender); 
 $user->attach($mobile_sender); 
 $user->create($user); 
 echo PHP_EOL; 

 // 用户忘记密码后重置密码，还需要通过站内小纸条通知用户
 $user->attach($web_sender); 
 $user->resetPassword(); 
 echo PHP_EOL; 

 // 用户变更了密码，但是不要给他的手机发短信
 $user->detach($mobile_sender); 
 $user->changePassword('654321'); 
 echo PHP_EOL;
```
# 运行结果
```php
 User::create 
向 user1@domain.com 发送电子邮件成功。内容是：你好张三你的新密码是 123456，请妥善保管
向 13610002000 发送短消息成功。内容是：你好张三你的新密码是 123456，请妥善保管

 User::resetPassword 
向 user1@domain.com 发送电子邮件成功。内容是：你好张三你的新密码是 363989，请妥善保管
向 13610002000 发送短消息成功。内容是：你好张三你的新密码是 363989，请妥善保管
这是 1 封站内小纸条。你好张三，你的新密码是 363989，请妥善保管

 User::changePassword 
向 user1@domain.com 发送电子邮件成功。内容是：你好张三你的新密码是 654321，请妥善保管
这是 1 封站内小纸条。你好张三，你的新密码是 654321，请妥善保管
```