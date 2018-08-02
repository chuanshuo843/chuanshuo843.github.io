---
title: PHP之双向链表
author: DuanEnJian
tags:
  - PHP
  - SPL标准库
categories:
  - 开发
abbrlink: 2340898584
date: 2017-12-28 19:58:00
---
SPL，PHP 标准库（Standard PHP Library） ，从 PHP 5.0 起内置的组件和接口，且从 PHP5.3 已逐渐的成熟。SPL 在所有的 PHP5 开发环境中被内置，同时无需任何设置。
<!-- more -->

# 双向链表原理图

{% asset_img 3582cdb94bcf6d45a65aa187d8446b77.jpg 原理图 %}
# SplDoublyLinkedList
双向链表是一种重要的线性存储结构，对于双向链表中的每个节点，不仅仅存储自己的信息，还要保存前驱和后继节点的地址。

PHP SPL中的SplDoublyLinkedList类提供了对双向链表的操作。
## 参考资料
 [PHP-SPL-SplDoublyLinkedList](http://php.net/manual/zh/class.spldoublylinkedlist.php)
## SplDoublyLinkedList类说明
```php
SplDoublyLinkedList implements Iterator  , ArrayAccess  , Countable  {
  
  public __construct ( void )
  public void add ( mixed $index , mixed $newval )
  //双链表的头部节点
  public mixed top ( void )
  //双链表的尾部节点
  public mixed bottom ( void )
  //双联表元素的个数
  public int count ( void )
  //检测双链表是否为空
  public bool isEmpty ( void )
  
  
  //当前节点索引
  public mixed key ( void )
  //移到上条记录
  public void prev ( void )
  //移到下条记录
  public void next ( void )
  //当前记录
  public mixed current ( void )
  //将指针指向迭代开始处
  public void rewind ( void )
  //检查双链表是否还有节点
  public bool valid ( void )
  
  //指定index处节点是否存在
  public bool offsetExists ( mixed $index )
  //获取指定index处节点值
  public mixed offsetGet ( mixed $index )
  //设置指定index处值
  public void offsetSet ( mixed $index , mixed $newval )
  //删除指定index处节点
  public void offsetUnset ( mixed $index )
  
  //从双链表的尾部弹出元素
  public mixed pop ( void )
  //添加元素到双链表的尾部
  public void push ( mixed $value )
  
  //序列化存储
  public string serialize ( void )
  //反序列化
  public void unserialize ( string $serialized )
  
  //设置迭代模式
  public void setIteratorMode ( int $mode )
  //获取迭代模式SplDoublyLinkedList::IT_MODE_LIFO (Stack style) SplDoublyLinkedList::IT_MODE_FIFO (Queue style)
  public int getIteratorMode ( void )
  
  //双链表的头部移除元素
  public mixed shift ( void )
  //双链表的头部添加元素
  public void unshift ( mixed $value )
  
}
```
## SplDoublyLinkedList使用
```php
$list = new SplDoublyLinkedList();
$list->push('a');
$list->push('b');
$list->push('c');
  
$list->unshift('top');
$list->shift();
  
print_r(array(
  'pop' => $list->pop(),
  'count' => $list->count(),
  'isEmpty' => $list->isEmpty(),
  'bottom' => $list->bottom(),
  'top' => $list->top()
));
  
$list->setIteratorMode(SplDoublyLinkedList::IT_MODE_FIFO);
print_r($list->getIteratorMode());
  
for($list->rewind(); $list->valid(); $list->next()) {
  echo $list->current().PHP_EOL;
}
  
print_r($a = $list->serialize());
//print_r($list->unserialize($a));
  
$list->offsetSet(0,'new one');
$list->offsetUnset(0);
print_r(array(
  'offsetExists' => $list->offsetExists(4),
  'offsetGet' => $list->offsetGet(0),
  
));
print_r($list);

//输出结果

Array
(
    [pop] => c
    [count] => 2
    [isEmpty] => 
    [bottom] => a
    [top] => b
)
0a
b
i:0;:s:1:"a";:s:1:"b";Array
(
    [offsetExists] => 
    [offsetGet] => b
)
SplDoublyLinkedList Object
(
    [flags:SplDoublyLinkedList:private] => 0
    [dllist:SplDoublyLinkedList:private] => Array
        (
            [0] => b
        )

)

```