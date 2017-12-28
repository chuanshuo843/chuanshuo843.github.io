title: PHP之队列-Queue
author: DuanEnJian
tags:
  - PHP
  - SPL标准库
categories:
  - 开发
date: 2017-12-28 20:19:00
---
SPL，PHP 标准库（Standard PHP Library） ，从 PHP 5.0 起内置的组件和接口，且从 PHP5.3 已逐渐的成熟。SPL 在所有的 PHP5 开发环境中被内置，同时无需任何设置。
<!-- more -->
# 队列原理图
{% asset_img 5eb305bda90d7af812900948d43e2545.png 原理图 %}
# SplQueue
队列是一种先进先出(FIFO)的数据结构。使用队列时插入在一端进行而删除在另一端进行。
PHP SPL中的SplQueue也是继承自SplDoublyLinkedList,并有自己的方法
## 参考资料
[PHP-SPL-SplQueue](http://php.net/manual/zh/class.splqueue.php)
## SplQueue类说明
```php
SplQueue extends SplDoublyLinkedList implements Iterator , ArrayAccess , Countable {
    /* 方法 */
    __construct ( void )
    mixed dequeue ( void )
    void enqueue ( mixed $value )
    void setIteratorMode ( int $mode )
    /* 继承的方法 */
    public void SplDoublyLinkedList::add ( mixed $index , mixed $newval )
    public mixed SplDoublyLinkedList::bottom ( void )
    public int SplDoublyLinkedList::count ( void )
    public mixed SplDoublyLinkedList::current ( void )
    public int SplDoublyLinkedList::getIteratorMode ( void )
    public bool SplDoublyLinkedList::isEmpty ( void )
    public mixed SplDoublyLinkedList::key ( void )
    public void SplDoublyLinkedList::next ( void )
    public bool SplDoublyLinkedList::offsetExists ( mixed $index )
    public mixed SplDoublyLinkedList::offsetGet ( mixed $index )
    public void SplDoublyLinkedList::offsetSet ( mixed $index , mixed $newval )
    public void SplDoublyLinkedList::offsetUnset ( mixed $index )
    public mixed SplDoublyLinkedList::pop ( void )
    public void SplDoublyLinkedList::prev ( void )
    public void SplDoublyLinkedList::push ( mixed $value )
    public void SplDoublyLinkedList::rewind ( void )
    public string SplDoublyLinkedList::serialize ( void )
    public void SplDoublyLinkedList::setIteratorMode ( int $mode )
    public mixed SplDoublyLinkedList::shift ( void )
    public mixed SplDoublyLinkedList::top ( void )
    public void SplDoublyLinkedList::unserialize ( string $serialized )
    public void SplDoublyLinkedList::unshift ( mixed $value )
    public bool SplDoublyLinkedList::valid ( void )
}
```
## SplQueue使用
```php
<?php

$obj = new SplQueue();

$obj -> enqueue('a');
$obj -> enqueue('b');
$obj -> enqueue('c');

echo 'bottom:'.$obj -> bottom().PHP_EOL;
echo 'top:'.$obj -> top();
echo '<br/>';

//队列里的offset=0是指向bottom位置
$obj -> offsetSet(0,'A');
echo 'bottom:'.$obj -> bottom();
echo '<br/>';

//队列里的rewind使得指针指向bottom所在位置的节点
$obj -> rewind();
echo 'current:'.$obj->current();
echo '<br/>';

while ($obj ->valid()) {
    echo $obj ->key().'=>'.$obj->current().PHP_EOL;
    $obj->next();//
}
echo '<br/>';

//dequeue操作从队列中提取bottom位置的节点，并返回，同时从队列里面删除该元素
echo 'dequeue obj:'.$obj->dequeue();
echo '<br/>';
echo 'bottom:'.$obj -> bottom().PHP_EOL;

//输出

bottom:a top:c
bottom:A
current:A
0=>A 1=>b 2=>c 
dequeue obj:A
bottom:b
```
# SplPriorityQueue
优先级队列是不同于先进先出队列的另一种队列，它每次从队列中取出的是具有最高优先权的元素， 这里的优先是指元素的某一属性优先，以比较为例，可能是较大的优先，也可能是较小的优先。 PHP实现的优先级队列默认是以大头堆实现，即较大的优先，如果要较小的优先，则需要继承SplPriorityQueue类，并重载compare方法。

PHP SPL中的SplPriorityQueue是基于堆实现的。和堆一样，也有int compare ( mixed $priority1 , mixed $priority2 )方法。

SplPriorityQueue实现了Iterator,Countable接口
## 参考资料
[PHP-SPL-SplPriorityQueue](http://php.net/manual/zh/class.splpriorityqueue.php)
## SplPriorityQueue类说明
```php
SplPriorityQueue implements Iterator , Countable {
    /* 方法 */
    public __construct ( void )
    public int compare ( mixed $priority1 , mixed $priority2 )
    public int count ( void )
    public mixed current ( void )
    public mixed extract ( void )
    public void insert ( mixed $value , mixed $priority )
    public bool isEmpty ( void )
    public mixed key ( void )
    public void next ( void )
    public void recoverFromCorruption ( void )
    public void rewind ( void )
    public void setExtractFlags ( int $flags )
    public mixed top ( void )
    public bool valid ( void )
}
```
## SplPriorityQueue使用
```php
$pq = new SplPriorityQueue();
 
$pq->insert('a', 10);
$pq->insert('b', 1);
$pq->insert('c', 8);
 
echo $pq->count() .PHP_EOL; //3
echo $pq->current() . PHP_EOL; //a
 
/**
 * 设置元素出队模式
 * SplPriorityQueue::EXTR_DATA 仅提取值
 * SplPriorityQueue::EXTR_PRIORITY 仅提取优先级
 * SplPriorityQueue::EXTR_BOTH 提取数组包含值和优先级
 */
$pq->setExtractFlags(SplPriorityQueue::EXTR_DATA);
 
while($pq->valid()) {
    print_r($pq->current());  //a  c  b
    $pq->next();
}

//输出

3
a
acb
```