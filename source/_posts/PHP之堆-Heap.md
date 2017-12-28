title: PHP之堆-Heap
author: DuanEnJian
tags:
  - PHP
  - SPL标准库
categories:
  - 开发
date: 2017-12-28 20:27:00
---
SPL，PHP 标准库（Standard PHP Library） ，从 PHP 5.0 起内置的组件和接口，且从 PHP5.3 已逐渐的成熟。SPL 在所有的 PHP5 开发环境中被内置，同时无需任何设置。

对于理解堆以及实现堆很重要的一点就是明白堆的表现形式，堆是树的一种，所以很自然的想到使用链表来实现堆，其实不然，由于我们需要频繁的对堆进行增加删除，所以一般堆的底层都是通过数组来实现，那么就有一个问题：数组如何表现出堆的结构呢？这里就有一个规则，即数组的第一个元素（即下标为0的元素）为堆的根节点，其他节点按照堆结构自上而下，自左而右依次表示为数组中的元素，这是一种既非前序也非后序，更非中序的遍历树的方式。
<!-- more -->
# 堆原理图
{% asset_img cf677d129fcf9912df6f2e7a1ee32a2c.jpg 原理图 %}
# SplHeap
堆、大头堆、小头堆和优先队列是同一类数据结构，都是基于堆的实现。 堆是一颗完全二叉树，常用于管理算法执行过程中的信息，应用场景包括堆排序，优先队列等。 堆分为大头堆和小头堆，在定义上的区别是父节点的值是大于还是小于子节点的值， 在SPL中，它们的区别以比较函数的不同体现，而比较函数的不同仅仅体现在比较时交换了下位置和函数名的不同。
## 参考资料
[PHP-SPL-SplHeap](http://php.net/manual/zh/class.splheap.php)
## SplHeap类说明
PHP的堆以数组的形式存储数据，默认初始化分配64个元素的内存空间，新元素插入时，如果当前元素的个数总和超过分配的值，则会将其空间扩大一倍，即*2。
```php
abstract SplHeap implements Iterator , Countable {
    /* 方法 */
    public __construct ( void )
    abstract protected int compare ( mixed $value1 , mixed $value2 )
    public int count ( void )
    public mixed current ( void )
    public mixed extract ( void )
    public void insert ( mixed $value )
    public bool isEmpty ( void )
    public mixed key ( void )
    public void next ( void )
    public void recoverFromCorruption ( void )
    public void rewind ( void )
    public mixed top ( void )
    public bool valid ( void )
}
```
## SplHeap使用
```php
<?php

class MySimpleHeap extends SplHeap
{
    //compare()方法用来比较两个元素的大小，绝对他们在堆中的位置
    public function  compare( $value1, $value2 ) {
        return ( $value1 - $value2 );
    }
}
 
$obj = new MySimpleHeap();
$obj->insert( 4 );
$obj->insert( 8 );
$obj->insert( 1 );
$obj->insert( 0 );
 
echo $obj->top();  //8
echo $obj->count(); //4
echo '<br/>';
 
foreach( $obj as $number ) {
    echo $number.PHP_EOL;
}

//输出
84
8 4 1 0
```
# SplMaxHeap(最大堆)、SplMinHeap(最小堆)
SplMaxHeap和SplMinHeap都是SplHeap类的子类，直接继承了SplHeap的所有方法和属性，各自实现了自己的compare方法。
```php
$minHeap = new SplMinHeap();  
$maxHeap = new SplMaxHeap();  
  
for ($i=1; $i<=10; $i++) {  
    $minHeap->insert(rand(1, 1000));  
    $maxHeap->insert(rand(1, 1000));  
}  
  
  
print_r("min heap!");  
print_r($minHeap);  
foreach ($minHeap as $value) {  
    print_r($value);  
}  
  
print_r("max heap!");  
print_r($maxHeap);  
foreach ($maxHeap as $value) {  
    print_r($value);  
}  
```
{% asset_img 400f6a02d1b4f7a11fc1503981d5ce2d.png %}