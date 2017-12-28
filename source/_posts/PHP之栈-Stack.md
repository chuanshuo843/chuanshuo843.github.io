title: PHP之栈-Stack
author: DuanEnJian
tags:
  - PHP
  - SPL标准库
categories:
  - 开发
date: 2017-12-28 20:06:00
---
SPL，PHP 标准库（Standard PHP Library） ，从 PHP 5.0 起内置的组件和接口，且从 PHP5.3 已逐渐的成熟。SPL 在所有的 PHP5 开发环境中被内置，同时无需任何设置。
<!-- more -->

# 栈(Stack)原理图

{% asset_img a0abefd4c7f94c39654613ebf26dcf27.jpg 原理图 %}
# SplStack
栈(Stack)是一种特殊的线性表，因为它只能在线性表的一端进行插入或删除元素(即进栈和出栈)。
栈是一种后进先出(LIFO)的数据结构。
PHP SPL中的SplStack继承自双向链表SplDoublyLinkedList。
## 参考资料
[PHP-SPL-SplStack](http://php.net/manual/zh/class.splstack.php)
## SplStack类说明
```php
SplStack extends SplDoublyLinkedList implements Iterator , ArrayAccess , Countable {
    /* 方法 */
    __construct ( void )
    /**
     *   设置迭代模式
     * （1）SplDoublyLinkedList::IT_MODE_LIFO | SplDoublyLinkedList::IT_MODE_KEEP （默认值,迭代后数据保存）
     * （2）SplDoublyLinkedList::IT_MODE_LIFO | SplDoublyLinkedList::IT_MODE_DELETE （迭代后数据删除）
     */
    void setIteratorMode ( int $mode )
    /* 继承的方法 */
    public void SplDoublyLinkedList::add ( mixed $index , mixed $newval )
    //尾部节点
    public mixed SplDoublyLinkedList::bottom ( void )
    //元素的个数
    public int SplDoublyLinkedList::count ( void )
    //当前记录
    public mixed SplDoublyLinkedList::current ( void )
    //获取迭代模式
    public int SplDoublyLinkedList::getIteratorMode ( void )
    //检测是否为空
    public bool SplDoublyLinkedList::isEmpty ( void )
    //当前节点索引
    public mixed SplDoublyLinkedList::key ( void )
    //移到下条记录
    public void SplDoublyLinkedList::next ( void )
    //指定index处节点是否存在
    public bool SplDoublyLinkedList::offsetExists ( mixed $index )
    //获取指定index处节点值
    public mixed SplDoublyLinkedList::offsetGet ( mixed $index )
    //设置指定index处值
    public void SplDoublyLinkedList::offsetSet ( mixed $index , mixed $newval )
    //删除指定index处节点
    public void SplDoublyLinkedList::offsetUnset ( mixed $index )
    //从尾部弹出元素
    public mixed SplDoublyLinkedList::pop ( void )
    //移到上条记录
    public void SplDoublyLinkedList::prev ( void )
    //添加元素到尾部
    public void SplDoublyLinkedList::push ( mixed $value )
    //将指针指向迭代开始处
    public void SplDoublyLinkedList::rewind ( void )
    //序列化存储
    public string SplDoublyLinkedList::serialize ( void )
    //设置迭代模式
    public void SplDoublyLinkedList::setIteratorMode ( int $mode )
    //头部移除元素
    public mixed SplDoublyLinkedList::shift ( void )
    //头部节点
    public mixed SplDoublyLinkedList::top ( void )
    //反序列化
    public void SplDoublyLinkedList::unserialize ( string $serialized )
    //头部添加元素
    public void SplDoublyLinkedList::unshift ( mixed $value )
    //检查是否还有节点
    public bool SplDoublyLinkedList::valid ( void )
}
```
## SplStack使用
```php
<?php
$stack = new SplStack();
$stack->push(1);
$stack->push(2);
$stack->push(3);

echo 'bottom:'.$stack -> bottom().PHP_EOL;
echo "top:".$stack->top().PHP_EOL;
//堆栈的offset=0,是top所在位置（即栈的末尾）
$stack -> offsetSet(0, 10);
echo "top:".$stack->top().'<br/>';

//堆栈的rewind和双向链表的rewind相反，堆栈的rewind使得当前指针指向top所在位置，而双向链表调用之后指向bottom所在位置
$stack -> rewind();
echo 'current:'.$stack->current().'<br/>';

$stack ->next();//堆栈的next操作使指针指向靠近bottom位置的下一个节点，而双向链表是靠近top的下一个节点
echo 'current:'.$stack ->current().'<br/>';

//遍历堆栈
$stack -> rewind();
while ($stack->valid()) {
    echo $stack->key().'=>'.$stack->current().PHP_EOL;
    $stack->next();//不从链表中删除元素
}
echo '<br/>';

echo $stack->pop() .'--';
echo $stack->pop() .'--';
echo $stack->pop() .'--';

//输出结果

bottom:1 top:3 top:10
current:10
current:2
2=>10 1=>2 0=>1 
10--2--1--

```